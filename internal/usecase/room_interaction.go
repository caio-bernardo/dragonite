package usecase

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type RoomInteractionService struct {
	canalRepo        CanalStorage
	eventoRepo       EventoStorage
	fedService       *FederationService
	authRuleResolver *AuthRuleResolver
	serverName       string
	keyID            string
	privateKey       ed25519.PrivateKey
	uow              WorkUnit
}

type GetMessagesResponse struct {
	Start string          `json:"start"`
	End   string          `json:"end,omitempty"`
	Chunk []domain.Evento `json:"chunk"`
	State []domain.Evento `json:"state,omitempty"`
}

func NewRoomInteractionService(canalRepo CanalStorage, eventoRepo EventoStorage, fedService *FederationService, authRuleResolver *AuthRuleResolver, uow WorkUnit, serverName, keyID string, privateKey ed25519.PrivateKey) *RoomInteractionService {
	return &RoomInteractionService{
		canalRepo:        canalRepo,
		eventoRepo:       eventoRepo,
		fedService:       fedService,
		authRuleResolver: authRuleResolver,
		uow:              uow,
		serverName:       serverName,
		keyID:            keyID,
		privateKey:       privateKey,
	}
}

type EventParams struct {
	RoomID    string
	SenderID  string
	Content   map[string]any
	EventType string
}

type StateParams struct {
	RoomID    string
	UserID    string
	EventType string
	StateKey  string
	Content   map[string]any
}

func (s *RoomInteractionService) SendStateEvent(ctx context.Context, params StateParams) (string, error) {
	// 1. Authorization: Check if the user is joined to the room
	status, err := s.canalRepo.GetUserMembership(ctx, params.RoomID, params.UserID)
	if err != nil || status != "join" {
		return "", types.ErrForbidden
	}
	// TODO: check powerlevel and if statekey starts with @ matches sender

	// 2. Build the Base State Event
	contentBytes, err := json.Marshal(params.Content)
	if err != nil {
		return "", fmt.Errorf("failed to marshal content: %w", err)
	}

	newEvent := &domain.Evento{
		CanalID:          params.RoomID,
		Sender:           params.UserID,
		Tipo:             params.EventType,
		StateKey:         &params.StateKey, // STATE events MUST have a state key (even if it's "")
		Content:          contentBytes,
		OrigemServidorTS: time.Now().UnixMilli(),
	}

	// ATOMIC DATABASE TRANSACTION (The 3-Step State Update)
	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
		// 3. Resolve DAG Dependencies (The Timeline and the VIP Pass)
		prevs, auths, err := s.authRuleResolver.ResolveEventDependencies(ctx, params.RoomID, params.UserID, params.EventType, &params.StateKey)
		if err != nil {
			return fmt.Errorf("failed to resolve DAG dependencies: %w", err)
		}
		newEvent.PrevEventos = prevs
		newEvent.AuthEventos = auths

		maxDepth, err := s.eventoRepo.GetMaxDepthFromEventos(ctx, prevs)
		if err != nil {
			return fmt.Errorf("failed to get event depth: %w", err)
		}
		newEvent.Depth = maxDepth + 1

		// 4. Cryptographic Hashing
		eventID, err := util.HashMatrixEvent(newEvent)
		if err != nil {
			return fmt.Errorf("failed to hash event: %w", err)
		}
		newEvent.ID = eventID

		signJSON, err := util.SignMatrixEvent(newEvent, s.serverName, s.keyID, s.privateKey)
		if err != nil {
			return fmt.Errorf("failed to sign event: %w", err)
		}
		newEvent.Signatures = signJSON
		// A. Save the historical event payload to the DAG
		if err := s.eventoRepo.SaveEvento(txCtx, newEvent); err != nil {
			return err
		}

		// B. Update the DAG Extremities (Move the timeline forward)
		if err := s.canalRepo.UpdateForwardExtremities(txCtx, params.RoomID, eventID, prevs); err != nil {
			return err
		}

		// C. Upsert the Current State (Overwrite the old state for this Type + StateKey)
		if err := s.canalRepo.UpsertCurrentState(txCtx, params.RoomID, params.EventType, params.StateKey, eventID); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return "", fmt.Errorf("transaction failed: %w", err)
	}

	// 6. Post-Transaction Side Effects
	// NOTE: Wake up local users listening on /sync so their UI updates instantly
	// Postgres handles notification on room level

	// Queue the state change to be pushed to remote servers
	_ = s.fedService.QueueOutgoing(ctx, *newEvent)

	return newEvent.ID, nil
}

func (s *RoomInteractionService) SendEvent(ctx context.Context, params EventParams) (string, error) {
	// 1. Authorization: Check if the user is joined to the room
	status, err := s.canalRepo.GetUserMembership(ctx, params.RoomID, params.SenderID)
	if err != nil || status != "join" {
		return "", types.ErrForbidden
	}

	// 2. Build the Base Event
	contentBytes, err := json.Marshal(params.Content)
	if err != nil {
		return "", fmt.Errorf("failed to marshal content: %w", err)
	}

	newEvent := &domain.Evento{
		CanalID:          params.RoomID,
		Sender:           params.SenderID,
		Tipo:             params.EventType,
		StateKey:         nil, // REGULAR events strictly have NO state key
		Content:          contentBytes,
		OrigemServidorTS: time.Now().UnixMilli(),
	}

	// ATOMIC DATABASE TRANSACTION
	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
		// 3. Resolve DAG Dependencies (The VIP Pass and the Timeline)
		prevs, auths, err := s.authRuleResolver.ResolveEventDependencies(ctx, params.RoomID, params.SenderID, params.EventType, nil)
		if err != nil {
			return fmt.Errorf("failed to resolve DAG dependencies: %w", err)
		}
		newEvent.PrevEventos = prevs
		newEvent.AuthEventos = auths

		maxDepth, err := s.eventoRepo.GetMaxDepthFromEventos(ctx, prevs)
		if err != nil {
			return fmt.Errorf("failed to get event depth: %w", err)
		}
		newEvent.Depth = maxDepth + 1

		// 4. Cryptographic Hashing
		eventID, err := util.HashMatrixEvent(newEvent)
		if err != nil {
			return fmt.Errorf("failed to hash event: %w", err)
		}
		newEvent.ID = eventID

		signJSON, err := util.SignMatrixEvent(newEvent, s.serverName, s.keyID, s.privateKey)
		if err != nil {
			return fmt.Errorf("failed to sign event: %w", err)
		}

		newEvent.Signatures = signJSON

		// A. Save the event payload
		if err := s.eventoRepo.SaveEvento(txCtx, newEvent); err != nil {
			return err
		}

		// B. Update the DAG Extremities
		// This query deletes the old extremities (prevs) and inserts the new EventID
		if err := s.canalRepo.UpdateForwardExtremities(txCtx, params.RoomID, eventID, prevs); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return "", fmt.Errorf("transaction failed: %w", err)
	}

	// 6. Post-Transaction Side Effects (Waking up the network)
	// Wake up local users listening on /sync
	// NOTE: postgres handles notification on room level

	// Queue the event to be pushed to remote servers
	_ = s.fedService.QueueOutgoing(ctx, *newEvent)

	return newEvent.ID, nil
}

func (s *RoomInteractionService) RetrieveSingleEvent(ctx context.Context, eventID string) (*domain.Evento, error) {
	evento, err := s.eventoRepo.GetEvento(ctx, eventID)
	if err != nil {
		return nil, err
	}
	return evento, nil
}

func (s *RoomInteractionService) BackfillRoomEvents(ctx context.Context, roomID string, limit int, eventIDs []string) ([]domain.Evento, error) {
	eventos, err := s.eventoRepo.GetEventsSince(ctx, roomID, limit, eventIDs)
	if err != nil {
		return nil, err
	}
	return eventos, nil
}

func (s *RoomInteractionService) GetMessages(ctx context.Context, roomID, userID, from, dir string, limit int) (*GetMessagesResponse, error) {
	// Verificar se o utilizador é membro da sala
	status, err := s.canalRepo.GetUserMembership(ctx, roomID, userID)
	if err != nil || status != "join" {
		return nil, types.ErrForbidden
	}

	// Converter o token "from" num stream_ordering (int64)
	var fromToken int64
	if from != "" {
		parsed, err := strconv.ParseInt(from, 10, 64)
		if err == nil {
			fromToken = parsed
		}
	}

	// Obter os eventos da base de dados usando o Storage
	eventos, err := s.eventoRepo.GetRoomMessagesHistory(ctx, roomID, fromToken, dir, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get messages history: %w", err)
	}

	// Determinar o token de paginação 'end' com base no último evento do chunk
	var endToken string
	if len(eventos) > 0 {
		lastEvent := eventos[len(eventos)-1]
		endToken = strconv.FormatInt(lastEvent.StreamOrdering, 10)
	} else {
		endToken = from // Se não houver mais eventos, o fim é igual ao início
	}

	return &GetMessagesResponse{
		Start: from,
		End:   endToken,
		Chunk: eventos,
	}, nil
}

// SendReceipt trata da lógica de negócio para recibos de leitura
func (s *RoomInteractionService) SendReceipt(ctx context.Context, userID, roomID, receiptType, eventID string) error {
	// O utilizador só pode enviar recibos de salas onde está ativamente (join)
	status, err := s.canalRepo.GetUserMembership(ctx, roomID, userID)
	if err != nil || status != "join" {
		return types.ErrForbidden
	}

	// Gravar no PostgreSQL
	ts := time.Now().UnixMilli()
	if err := s.eventoRepo.SaveReceipt(ctx, userID, roomID, receiptType, eventID, ts); err != nil {
		return fmt.Errorf("failed to persist receipt: %w", err)
	}

	return nil
}
