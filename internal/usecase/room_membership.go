package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type RoomMembershipService struct {
	uow              WorkUnit
	authRuleResolver *AuthRuleResolver
	canalRepo        CanalStorage
	eventRepo        EventoStorage
	fedService       *FederationService
	stateResolver    StateResolver
}

func NewRoomMembershipService(uow WorkUnit, canalRepo CanalStorage, eventRepo EventoStorage, authRuleResolver *AuthRuleResolver, fedService *FederationService, stateResolver StateResolver) *RoomMembershipService {
	return &RoomMembershipService{
		uow:              uow,
		authRuleResolver: authRuleResolver,
		canalRepo:        canalRepo,
		eventRepo:        eventRepo,
		fedService:       fedService,
		stateResolver:    stateResolver,
	}
}

func (s *RoomMembershipService) LeaveRoom(ctx context.Context, userID, roomID string) error {
	// 1. Verify they are actually in the room (or invited)
	currentStatus, err := s.canalRepo.GetUserMembership(ctx, roomID, userID)
	if err != nil || (currentStatus != "join" && currentStatus != "invite") {
		return fmt.Errorf("user is not in a state to leave this room")
	}

	// 2. Build the Leave Event
	leaveEvent := buildLeaveEvent(roomID, userID)

	// Transactional Save
	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
		// 3. Resolve DAG dependencies (Use the method we built earlier)
		prevs, auths, err := s.authRuleResolver.ResolveEventDependencies(ctx, roomID, userID, "m.room.member", &userID)
		if err != nil {
			return err
		}
		leaveEvent.PrevEventos = prevs
		leaveEvent.AuthEventos = auths
		maxDepth, err := s.eventRepo.GetMaxDepthFromEventos(ctx, prevs)
		if err != nil {
			return fmt.Errorf("failed to get event depth: %w", err)
		}
		leaveEvent.Depth = maxDepth + 1

		// 4. Hash it
		eventID, _ := util.HashMatrixEvent(leaveEvent)
		leaveEvent.ID = eventID
		// A. Save the event to the DAG
		if err := s.eventRepo.SaveEvento(txCtx, leaveEvent); err != nil {
			return err
		}
		// Update DAG Extremities
		if err := s.canalRepo.UpdateForwardExtremities(txCtx, roomID, eventID, prevs); err != nil {
			return err
		}

		// Update the Room's Current State for this state_key
		if err := s.canalRepo.UpsertCurrentState(txCtx, roomID, "m.room.member", userID, eventID); err != nil {
			return err
		}

		// B. Update the denormalized fast-lookup table
		if err := s.canalRepo.UpsertMembership(txCtx, roomID, userID, "leave", eventID); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return err
	}
	// local clients notified by notifier
	// 6. Notify remote servers
	_ = s.fedService.QueueOutgoing(ctx, *leaveEvent)

	return nil
}

// GetJoinedRooms retorna os IDs das salas em que o usuário tem membership "join"
// Usado por GET /_matrix/client/v3/joined_rooms
func (s *RoomMembershipService) GetJoinedRooms(ctx context.Context, userID string) ([]string, error) {
	roomIDs, err := s.canalRepo.GetUserJoinedRooms(ctx, userID)
	if err != nil {
		return nil, err
	}
	if roomIDs == nil {
		// evita serializar "null" no JSON quando o usuário não está em nenhuma sala
		roomIDs = []string{}
	}
	return roomIDs, nil
}

func (s *RoomMembershipService) JoinLocalRoom(ctx context.Context, userID, roomID string) error {

	// 1. Fetch the Join Rules
	joinRule, err := s.canalRepo.GetJoinRule(ctx, roomID)
	if err != nil {
		return fmt.Errorf("Failure: %w", err)
	}

	// 2. Validate Access
	if joinRule == "invite" || joinRule == "private" {
		// They MUST have a pending invite in our database
		status, _ := s.canalRepo.GetUserMembership(ctx, roomID, userID)
		if status != "invite" {
			return fmt.Errorf("M_FORBIDDEN: You must be invited to join this room")
		}
	} else if joinRule != "public" {
		return fmt.Errorf("M_FORBIDDEN: Room is not public")
	}

	// 3. Build the Join Event

	joinEvent := buildJoinEvent(roomID, userID)

	// Transactional Save
	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
		// 4. Resolve DAG Dependencies
		prevs, auths, err := s.authRuleResolver.ResolveEventDependencies(ctx, roomID, userID, "m.room.member", &userID)
		if err != nil {
			return err
		}
		joinEvent.PrevEventos = prevs
		joinEvent.AuthEventos = auths
		maxDepth, err := s.eventRepo.GetMaxDepthFromEventos(ctx, prevs)
		if err != nil {
			return fmt.Errorf("failed to get event depth: %w", err)
		}
		joinEvent.Depth = maxDepth + 1
		// 5. Hash it
		eventID, _ := util.HashMatrixEvent(joinEvent)
		joinEvent.ID = eventID
		if err := s.eventRepo.SaveEvento(txCtx, joinEvent); err != nil {
			return err
		}

		// Update DAG Extremities
		if err := s.canalRepo.UpdateForwardExtremities(txCtx, roomID, eventID, prevs); err != nil {
			return err
		}

		// Update the Room's Current State for this state_key
		if err := s.canalRepo.UpsertCurrentState(txCtx, roomID, "m.room.member", userID, eventID); err != nil {
			return err
		}

		// Update their status from "invite" (or null) to "join"
		if err := s.canalRepo.UpsertMembership(txCtx, roomID, userID, "join", eventID); err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		return err
	}

	// 7. Notify remote users
	_ = s.fedService.QueueOutgoing(ctx, *joinEvent)
	return nil
}

func (s *RoomMembershipService) JoinRemoteRoom(ctx context.Context, userID, roomID, remoteServer string) error {
	// 1. Send /make_join federation request to the remote server
	// (You'll need a client method on s.fedService or a transport layer to do this)
	protoEvent, err := s.fedService.MakeJoinCall(ctx, remoteServer, roomID, userID)
	if err != nil {
		return fmt.Errorf("federated make_join failed: %w", err)
	}

	// 2. Prepare, Hash and Sign the join event locally
	protoEvent.OrigemServidorTS = time.Now().UnixMilli()

	eventID, err := util.HashMatrixEvent(protoEvent)
	if err != nil {
		return fmt.Errorf("failed to hash remote join event: %w", err)
	}
	protoEvent.ID = eventID

	// Assuming RoomMembershipService is updated to possess your server keys similarly to RoomInteractionService
	signatures, err := util.SignMatrixEvent(protoEvent, s.fedService.serverName, s.fedService.keyID, s.fedService.privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign remote join event: %w", err)
	}
	protoEvent.Signatures = signatures

	// 3. Send /send_join back to the remote server
	// This request should return the room's complete active state and history context
	roomStateContext, err := s.fedService.SendJoinCall(ctx, remoteServer, roomID, protoEvent)
	if err != nil {
		return fmt.Errorf("federated send_join failed: %w", err)
	}

	// 4. PREPARE FOR STATE RESOLUTION V2
	// Instead of blindly trusting the remote server's state block, we organize
	// the received events into lookup maps for authorization and DAG sorting.
	eventsMap := make(map[string]*domain.Evento)
	authEventsMap := make(map[string]*domain.Evento)

	for i := range roomStateContext.AuthChain {
		ev := &roomStateContext.AuthChain[i]
		authEventsMap[ev.ID] = ev
	}

	remoteStateMap := make(domain.StateMap)
	for i := range roomStateContext.StateEvents {
		ev := &roomStateContext.StateEvents[i]
		eventsMap[ev.ID] = ev
		if ev.StateKey != nil {
			tuple := domain.NewStateTuple(ev.Tipo, ev.StateKey)
			remoteStateMap[tuple] = ev.ID
		}
	}
	// Include our newly generated join event in the known events map
	eventsMap[protoEvent.ID] = protoEvent

	// 5. ATOMIC TRANSACTION: Reconcile, Resolve, and Persist
	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
		// A. Ensure room metadata exists locally (create stub if first time seeing it)
		if _, err := s.canalRepo.GetByID(txCtx, roomID); err != nil {
			// Create room metadata locally if absent
			_, _ = s.canalRepo.Create(txCtx, roomID, protoEvent.Sender)
		}

		// B. Check if we already have any local state for this room in our DB
		// (e.g., if we previously left the room or received historical invites)
		localStateEvents, err := s.eventRepo.GetCurrentStateEvents(txCtx, roomID)
		localStateMap := make(domain.StateMap)
		if err == nil && len(localStateEvents) > 0 {
			for i := range localStateEvents {
				ev := &localStateEvents[i]
				eventsMap[ev.ID] = ev
				if ev.StateKey != nil {
					tuple := domain.NewStateTuple(ev.Tipo, ev.StateKey)
					localStateMap[tuple] = ev.ID
				}
			}
		}

		// C. Persist all historical AuthChain and StateEvents to our local event store
		for _, authEv := range roomStateContext.AuthChain {
			if err := s.eventRepo.SaveEvento(txCtx, &authEv); err != nil {
				return fmt.Errorf("failed to save auth chain event %s: %w", authEv.ID, err)
			}
		}
		for _, stateEv := range roomStateContext.StateEvents {
			if err := s.eventRepo.SaveEvento(txCtx, &stateEv); err != nil {
				return fmt.Errorf("failed to save state event %s: %w", stateEv.ID, err)
			}
		}
		if err := s.eventRepo.SaveEvento(txCtx, protoEvent); err != nil {
			return fmt.Errorf("failed to save join event %s: %w", protoEvent.ID, err)
		}

		// D. STATE RESOLUTION V2: Execute consensus between remote state and any local state
		stateSets := []domain.StateMap{remoteStateMap}
		if len(localStateMap) > 0 {
			stateSets = append(stateSets, localStateMap)
		}

		input := domain.StateResolutionInput{
			RoomID:        roomID,
			StateSets:     stateSets,
			AuthEventsMap: authEventsMap,
			EventsMap:     eventsMap,
		}

		resolvedState, err := s.stateResolver.Resolve(txCtx, input)
		if err != nil {
			return fmt.Errorf("state resolution v2 failed during remote join: %w", err)
		}

		// E. Ensure our new join event is reflected in the winning state map
		joinTuple := domain.NewStateTuple("m.room.member", &userID)
		resolvedState[joinTuple] = protoEvent.ID

		// F. Persist ONLY the mathematically verified consensus state as ground-truth
		for tuple, winningID := range resolvedState {
			if err := s.canalRepo.UpsertCurrentState(txCtx, roomID, tuple.EventType, tuple.StateKey, winningID); err != nil {
				return fmt.Errorf("failed to upsert resolved state %s|%s: %w", tuple.EventType, tuple.StateKey, err)
			}
		}

		// G. Update local DAG forward extremities and user membership status
		if err := s.canalRepo.UpdateForwardExtremities(txCtx, roomID, protoEvent.ID, protoEvent.PrevEventos); err != nil {
			return fmt.Errorf("failed to update forward extremities: %w", err)
		}
		if err := s.canalRepo.UpsertMembership(txCtx, roomID, userID, "join", protoEvent.ID); err != nil {
			return fmt.Errorf("failed to upsert membership: %w", err)
		}

		return nil
	})

	return err
}

// InviteUser convida um usuário (local ou remoto) a participar da sala, criando um evento
// m.room.member com membership "invite". Para convidados remotos, o evento é assinado
// localmente e enviado ao homeserver do convidado via
func (s *RoomMembershipService) InviteUser(ctx context.Context, roomID, inviterID, inviteeID, reason string) error {
	// 1. O inviter precisa estar atualmente na sala
	inviterStatus, err := s.canalRepo.GetUserMembership(ctx, roomID, inviterID)
	if err != nil {
		return fmt.Errorf("failed to check inviter membership: %w", err)
	}
	if inviterStatus != "join" {
		return fmt.Errorf("%w: inviter is not currently in the room", types.ErrForbidden)
	}

	// 2. O convidado não pode já ser membro nem estar banido
	inviteeStatus, err := s.canalRepo.GetUserMembership(ctx, roomID, inviteeID)
	if err != nil {
		return fmt.Errorf("failed to check invitee membership: %w", err)
	}
	if inviteeStatus == "ban" {
		return fmt.Errorf("%w: user is banned from the room", types.ErrForbidden)
	}
	if inviteeStatus == "join" {
		return fmt.Errorf("%w: user is already a member of the room", types.ErrForbidden)
	}

	// 3. Power level do inviter precisa ser suficiente para convidar
	if err := s.checkInvitePowerLevel(ctx, roomID, inviterID); err != nil {
		return err
	}

	// 4. Monta o evento m.room.member (invite)
	content := map[string]any{"membership": "invite"}
	if reason != "" {
		content["reason"] = reason
	}
	inviteEvent := newBaseEvent(roomID, inviterID, string(types.Member), &inviteeID, content)

	// 5. Resolve dependências do DAG
	prevs, auths, err := s.authRuleResolver.ResolveEventDependencies(ctx, roomID, inviterID, "m.room.member", &inviteeID)
	if err != nil {
		return err
	}
	inviteEvent.PrevEventos = prevs
	inviteEvent.AuthEventos = auths
	maxDepth, err := s.eventRepo.GetMaxDepthFromEventos(ctx, prevs)
	if err != nil {
		return fmt.Errorf("failed to get event depth: %w", err)
	}
	inviteEvent.Depth = maxDepth + 1

	eventID, err := util.HashMatrixEvent(inviteEvent)
	if err != nil {
		return fmt.Errorf("failed to hash invite event: %w", err)
	}
	inviteEvent.ID = eventID

	// 6. Se o convidado for de um servidor remoto, executa o handshake da federação:
	// assina localmente, envia ao homeserver dele para contra-assinatura e usa o evento
	// resultante (com ambas as assinaturas) como definitivo
	if util.IsRemoteUser(inviteeID, s.fedService.serverName) {
		sigs, err := util.SignMatrixEvent(inviteEvent, s.fedService.serverName, s.fedService.keyID, s.fedService.privateKey)
		if err != nil {
			return fmt.Errorf("failed to sign invite event: %w", err)
		}
		inviteEvent.Signatures = sigs

		canal, err := s.canalRepo.GetByID(ctx, roomID)
		if err != nil {
			return fmt.Errorf("failed to look up room: %w", err)
		}
		roomVersion := "11"
		if canal != nil && canal.Versao != "" {
			roomVersion = canal.Versao
		}

		remoteServer := util.ExtractDomainFromUserID(inviteeID)
		signedEvent, err := s.fedService.SendInviteCall(ctx, remoteServer, roomID, roomVersion, inviteEvent, s.buildInviteRoomState(ctx, roomID))
		if err != nil {
			return fmt.Errorf("federated invite failed: %w", err)
		}
		inviteEvent = signedEvent
	}

	// 7. Persistência transacional
	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
		if err := s.eventRepo.SaveEvento(txCtx, inviteEvent); err != nil {
			return err
		}
		if err := s.canalRepo.UpdateForwardExtremities(txCtx, roomID, inviteEvent.ID, inviteEvent.PrevEventos); err != nil {
			return err
		}
		if err := s.canalRepo.UpsertCurrentState(txCtx, roomID, "m.room.member", inviteeID, inviteEvent.ID); err != nil {
			return err
		}
		if err := s.canalRepo.UpsertMembership(txCtx, roomID, inviteeID, "invite", inviteEvent.ID); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	// 8. Notifica os demais servidores já participantes da sala sobre o novo convite
	_ = s.fedService.QueueOutgoing(ctx, *inviteEvent)

	return nil
}

// checkInvitePowerLevel verifica se o inviter tem nível de poder suficiente (m.room.power_levels.invite).
func (s *RoomMembershipService) checkInvitePowerLevel(ctx context.Context, roomID, inviterID string) error {
	eventID, found := s.canalRepo.GetStateEventID(ctx, roomID, "m.room.power_levels", "")
	if !found {
		// Sem power_levels definido: usa os defaults da spec (invite = 0), sempre permitido
		return nil
	}

	plEvent, err := s.eventRepo.GetEvento(ctx, eventID)
	if err != nil {
		return fmt.Errorf("failed to fetch power levels event: %w", err)
	}

	var pl struct {
		Invite       *int           `json:"invite"`
		UsersDefault *int           `json:"users_default"`
		Users        map[string]int `json:"users"`
	}
	if err := json.Unmarshal(plEvent.Content, &pl); err != nil {
		return fmt.Errorf("failed to parse power levels content: %w", err)
	}

	inviteLevel := 0
	if pl.Invite != nil {
		inviteLevel = *pl.Invite
	}
	usersDefault := 0
	if pl.UsersDefault != nil {
		usersDefault = *pl.UsersDefault
	}

	inviterLevel := usersDefault
	if lvl, ok := pl.Users[inviterID]; ok {
		inviterLevel = lvl
	}

	if inviterLevel < inviteLevel {
		return fmt.Errorf("%w: insufficient power level to invite", types.ErrForbidden)
	}
	return nil
}

// buildInviteRoomState monta um subconjunto ("stripped state") do estado atual da sala,
// enviado junto ao convite federado para que o servidor do convidado possa exibir uma
// prévia da sala (nome, tópico, avatar etc.) antes mesmo dele aceitar o convite
func (s *RoomMembershipService) buildInviteRoomState(ctx context.Context, roomID string) []domain.StrippedEvento {
	relevantTypes := []string{
		"m.room.create",
		"m.room.join_rules",
		"m.room.canonical_alias",
		"m.room.name",
		"m.room.avatar",
		"m.room.topic",
		"m.room.encryption",
	}

	stripped := make([]domain.StrippedEvento, 0, len(relevantTypes))
	for _, t := range relevantTypes {
		eventID, found := s.canalRepo.GetStateEventID(ctx, roomID, t, "")
		if !found {
			continue
		}
		ev, err := s.eventRepo.GetEvento(ctx, eventID)
		if err != nil || ev == nil {
			continue
		}
		stripped = append(stripped, domain.StrippedEvento{
			Tipo:     ev.Tipo,
			Content:  ev.Content,
			StateKey: ev.StateKey,
			Sender:   ev.Sender,
		})
	}
	return stripped
}
