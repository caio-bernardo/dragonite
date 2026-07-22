package usecase

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/util"
)

// mirrors InitialStateEvents
type StateEventParams struct {
	StateKey *string
	Type     string
	Content  map[string]any
}

type CreateRoomParams struct {
	CreatorID    string
	Visibility   string
	Alias        string
	Name         string
	Version      string
	Topic        string
	Invite       []string
	IsDirect     bool
	InitialState []StateEventParams
	Preset       *string
}

type RoomAdminService struct {
	serverName string
	keyID      string
	privateKey ed25519.PrivateKey

	uow               WorkUnit
	membershipService *RoomMembershipService
	fedService        *FederationService
	usuarioStore      UsuarioStorage
	canalStore        CanalStorage
	eventoStore       EventoStorage
	usuarioRepo       UsuarioStorage
}

func NewRoomAdminService(serverName, keyID string, privateKey ed25519.PrivateKey, uow WorkUnit, fedService *FederationService, canalStore CanalStorage, eventoStore EventoStorage, usuarioStore UsuarioStorage, usuarioRepo UsuarioStorage, membershipService *RoomMembershipService) *RoomAdminService {
	return &RoomAdminService{
		serverName:        serverName,
		keyID:             keyID,
		privateKey:        privateKey,
		uow:               uow,
		fedService:        fedService,
		usuarioStore:      usuarioStore,
		canalStore:        canalStore,
		eventoStore:       eventoStore,
		usuarioRepo:       usuarioRepo,
		membershipService: membershipService,
	}
}

func (s *RoomAdminService) CreateRoom(ctx context.Context, props CreateRoomParams) (*domain.Canal, error) {
	roomID := util.CreateRoomID(s.serverName)

	var eventsToSave []*domain.Evento
	// m.room.create
	var version string
	if props.Version != "" {
		version = props.Version
	} else {
		version = "11"
	}
	eventsToSave = append(eventsToSave, buildCreateEvent(roomID, props.CreatorID, version))

	var displayName, avatarURL string
	if profile, err := s.usuarioRepo.GetProfileByID(ctx, props.CreatorID); err == nil && profile != nil {
		if profile.DisplayName != nil {
			displayName = *profile.DisplayName
		}
		if profile.AvatarURL != nil {
			avatarURL = *profile.AvatarURL
		}
	}
	// m.room.member
	creatorJoinEvent := buildJoinEvent(roomID, props.CreatorID, displayName, avatarURL)
	eventsToSave = append(eventsToSave, creatorJoinEvent)
	// m.room.power_levels
	eventsToSave = append(eventsToSave, buildPowerLevelEvent(roomID, props.CreatorID))
	// m.room.join_rules
	present := "private"
	if props.Preset != nil {
		present = *props.Preset
	}
	var rulesEvent *domain.Evento
	switch present {
	case "public_chat":
		rulesEvent = buildJoinRulesEvent(roomID, props.CreatorID, "public")
	case "private_chat":
		// ALTERADO DE "private" PARA "invite"
		rulesEvent = buildJoinRulesEvent(roomID, props.CreatorID, "invite")
	default:
		// ALTERADO DE "private" PARA "invite"
		rulesEvent = buildJoinRulesEvent(roomID, props.CreatorID, "invite")
	}
	eventsToSave = append(eventsToSave, rulesEvent)

	// m.room.name
	if props.Name != "" {
		eventsToSave = append(eventsToSave, buildNameEvent(roomID, props.CreatorID, props.Name))
	}
	// m.room.topic
	if props.Topic != "" {
		eventsToSave = append(eventsToSave, buildTopicEvent(roomID, props.CreatorID, props.Topic))
	}
	//  m.room.canonical_alias
	var fullAlias string
	if props.Alias != "" {
		fullAlias = fmt.Sprintf("#%s:%s", props.Alias, s.serverName)
		eventsToSave = append(eventsToSave, buildAliasEvent(roomID, props.CreatorID, fullAlias))
	}

	// initial state
	customEvents := buildInitialStateEvents(roomID, props.CreatorID, props.InitialState)
	eventsToSave = append(eventsToSave, customEvents...)

	if err := linkAndHashGenesis(eventsToSave, s.serverName, s.keyID, s.privateKey); err != nil {
		return nil, err
	}

	err := s.uow.Execute(ctx, func(txCtx context.Context) error {
		// cria o metadados da sala
		if _, err := s.canalStore.Create(txCtx, roomID, props.CreatorID, version); err != nil {
			return err
		}

		// sava cada um dos eventos
		for _, event := range eventsToSave {
			if err := s.eventoStore.SaveEvento(txCtx, event); err != nil {
				return err
			}

			if event.StateKey != nil {
				if err := s.canalStore.UpsertCurrentState(txCtx, roomID, event.Tipo, *event.StateKey, event.ID); err != nil {
					return err
				}
			}
		}

		// atualiza a extremidade do último evento
		lastEvent := eventsToSave[len(eventsToSave)-1]
		if err := s.canalStore.UpdateForwardExtremities(txCtx, roomID, lastEvent.ID, lastEvent.PrevEventos); err != nil {
			return err
		}

		// 4. Popula a tabela Canal_Membership para que o Notifier funcione
		if err := s.canalStore.UpsertMembership(txCtx, roomID, props.CreatorID, "join", creatorJoinEvent.ID); err != nil {
			return err
		}

		// insere alias
		if fullAlias != "" {
			if err := s.canalStore.SaveAlias(txCtx, roomID, fullAlias); err != nil {
				return err
			}
		}

		if props.IsDirect && len(props.Invite) > 0 {
			s.usuarioStore.AddDirectMessage(txCtx, props.CreatorID, props.Invite[0], roomID)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// publica convites diretamente aos usuários
	for _, invitee := range props.Invite {
		err := s.membershipService.InviteUser(ctx, roomID, props.CreatorID, invitee, "", props.IsDirect)
		if err != nil {
			return nil, err
		}
	}

	// Se tudo deu certo, pega o canal e retorna
	canal, err := s.canalStore.GetByID(ctx, roomID)
	if err != nil {
		return nil, err
	}
	return canal, nil
}
