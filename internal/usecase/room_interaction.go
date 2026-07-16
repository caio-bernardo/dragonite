package usecase

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
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

// JoinedMemberProfile representa o formato exigido pelo endpoint joined_members
type JoinedMemberProfile struct {
	DisplayName *string `json:"display_name,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
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
		// 1. Tentar primeiro interpretar usando o formato padrão de SyncToken do Matrix (ex: "s15_0_0")
		token := domain.ParseToken(from)
		if token.TimelinePosition != 0 {
			fromToken = token.TimelinePosition
		} else if parsed, err := strconv.ParseInt(from, 10, 64); err == nil {
			// 2. Fallback caso o cliente tenha passado um número puro (ex: "15")
			fromToken = parsed
		}
	}

	// Obter os eventos da base de dados usando o Storage
	eventos, err := s.eventoRepo.GetRoomMessagesHistory(ctx, roomID, fromToken, dir, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get messages history: %w", err)
	}

	if eventos == nil {
		eventos = []domain.Evento{}
	}

	// Determinar o token de paginação 'end' com base no último evento do chunk
	var endToken string
	if len(eventos) > 0 {
		var lastEvent domain.Evento
		if dir == "b" {
			lastEvent = eventos[0]
		} else {
			lastEvent = eventos[len(eventos)-1]
		}
		// IMPORTANT: O token gerado DEVE ser formatado como SyncToken para consistência no cliente
		endToken = domain.SyncToken{TimelinePosition: lastEvent.StreamOrdering}.Encode()
	} else {
		endToken = ""
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

func (s *RoomInteractionService) GetEvent(ctx context.Context, userID, roomID, eventID string) (*domain.Evento, error) {

	status, err := s.canalRepo.GetUserMembership(ctx, roomID, userID)
	if err != nil || status != "join" {
		return nil, types.ErrForbidden
	}

	evento, err := s.eventoRepo.GetEvento(ctx, eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch event: %w", err)
	}

	if evento.CanalID != roomID {
		return nil, types.ErrForbidden
	}

	return evento, nil
}

// GetRoomState retorna todos os eventos de estado atuais da sala, se o utilizador tiver permissão
func (s *RoomInteractionService) GetRoomState(ctx context.Context, userID, roomID string) ([]domain.Evento, error) {

	status, err := s.canalRepo.GetUserMembership(ctx, roomID, userID)
	if err != nil || status != "join" {
		return nil, types.ErrForbidden
	}

	stateEvents, err := s.eventoRepo.GetCurrentStateEvents(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch current state events: %w", err)
	}

	if stateEvents == nil {
		stateEvents = []domain.Evento{}
	}

	return stateEvents, nil
}

// GetRoomMembers retorna a lista de membros filtrada
func (s *RoomInteractionService) GetRoomMembers(ctx context.Context, userID, roomID, membershipFilter, notMembershipFilter string) ([]domain.Evento, error) {
	// Verificar permissões (se está na sala)
	status, err := s.canalRepo.GetUserMembership(ctx, roomID, userID)
	if err != nil || status != "join" {
		return nil, types.ErrForbidden
	}

	// Obter todos os eventos m.room.member da base de dados
	memberEvents, err := s.eventoRepo.GetRoomMemberEvents(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch member events: %w", err)
	}

	// Se não houver filtros, devolvemos tudo
	if membershipFilter == "" && notMembershipFilter == "" {
		if memberEvents == nil {
			return []domain.Evento{}, nil
		}
		return memberEvents, nil
	}

	// Filtrar na memória (interpretar o JSON do Content para extrair a "membership")
	var filtered []domain.Evento
	for _, ev := range memberEvents {
		var content map[string]interface{}

		// Converte a string de Content para um Mapa
		if err := json.Unmarshal([]byte(ev.Content), &content); err != nil {
			continue // Se houver erro de formatação num evento, ignoramos
		}

		memState, ok := content["membership"].(string)
		if !ok {
			continue // Ignora eventos que não tenham o campo membership
		}

		// Aplica a lógica dos filtros exigidos pela especificação
		if membershipFilter != "" && memState != membershipFilter {
			continue
		}
		if notMembershipFilter != "" && memState == notMembershipFilter {
			continue
		}

		filtered = append(filtered, ev)
	}

	if filtered == nil {
		return []domain.Evento{}, nil
	}

	return filtered, nil
}

// GetJoinedMembers retorna o mapa de membros atualmente juntos (join) na sala
func (s *RoomInteractionService) GetJoinedMembers(ctx context.Context, userID, roomID string) (map[string]JoinedMemberProfile, error) {
	// Verificar permissões
	status, err := s.canalRepo.GetUserMembership(ctx, roomID, userID)
	if err != nil || status != "join" {
		return nil, types.ErrForbidden
	}

	// Buscar eventos m.room.member da sala (reutilizando a nossa função super rápida!)
	memberEvents, err := s.eventoRepo.GetRoomMemberEvents(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch member events: %w", err)
	}

	// Inicializar o mapa (A key será o User ID)
	joined := make(map[string]JoinedMemberProfile)

	for _, ev := range memberEvents {
		// Proteção: Eventos de membro devem ter sempre um state_key (que é o ID do utilizador alvo)
		if ev.StateKey == nil || *ev.StateKey == "" {
			continue
		}

		// Estrutura inline para extrair apenas o que precisamos do Content do evento
		var content struct {
			Membership  string  `json:"membership"`
			DisplayName *string `json:"displayname"` // Nota: no evento Matrix, escreve-se tudo junto
			AvatarURL   *string `json:"avatar_url"`
		}

		if err := json.Unmarshal([]byte(ev.Content), &content); err != nil {
			continue // Ignora lixo ou JSON malformado
		}

		// Apenas nos interessam os membros que estão com membership == "join"
		if content.Membership == "join" {
			joined[*ev.StateKey] = JoinedMemberProfile{
				DisplayName: content.DisplayName,
				AvatarURL:   content.AvatarURL,
			}
		}
	}

	return joined, nil
}

// ErrStateNotFound é retornado quando não existe state event com o tipo/chave pedidos
var ErrStateNotFound = errors.New("state event not found")

func (s *RoomInteractionService) GetStateEventContent(ctx context.Context, roomID, userID, eventType, stateKey string) (*domain.Evento, error) {
	status, found, err := s.canalRepo.GetUserMembershipRecord(ctx, roomID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}
	// 403: nunca teve nenhum registro de membership nessa sala
	if !found || (status != "join" && status != "leave") {
		return nil, types.ErrForbidden
	}

	// TODO: quando status == "leave", buscar o estado histórico no momento em que o
	// usuário saiu (via GetStateAndAuthChainIDs com o event_id do leave), em vez do
	// estado atual da sala. Requer expor o event_id da membership via CanalStorage
	// (já persistido por UpsertMembership, mas não exposto para leitura hoje)
	eventID, stateFound := s.canalRepo.GetStateEventID(ctx, roomID, eventType, stateKey)
	if !stateFound {
		return nil, ErrStateNotFound
	}

	evento, err := s.eventoRepo.GetEvento(ctx, eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch state event: %w", err)
	}
	return evento, nil
}
