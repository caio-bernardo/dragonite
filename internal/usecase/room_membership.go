package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/caio-bernardo/dragonite/internal/util"
)

type RoomMembershipService struct {
	uow              WorkUnit
	authRuleResolver *AuthRuleResolver
	canalRepo        CanalStorage
	eventRepo        EventoStorage
	fedService       *FederationService
}

func NewRoomMembershipService(uow WorkUnit, canalRepo CanalStorage, eventRepo EventoStorage, authRuleResolver *AuthRuleResolver, fedService *FederationService) *RoomMembershipService {
	return &RoomMembershipService{
		uow:              uow,
		authRuleResolver: authRuleResolver,
		canalRepo:        canalRepo,
		eventRepo:        eventRepo,
		fedService:       fedService,
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

	// 5. Transactional Save
	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
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
	// TODO: 6. Notify remote servers

	return nil
}

func (s *RoomMembershipService) JoinLocalRoom(ctx context.Context, userID, roomID string) error {

	// 1. Fetch the Join Rules
	joinRule, err := s.canalRepo.GetJoinRule(ctx, roomID)
	if err != nil {
		return fmt.Errorf("room not found or missing join rules")
	}

	// 2. Validate Access
	if joinRule == "invite" {
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

	// 6. Transactional Save
	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
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

	// 4. Transactional catch-up and persistence
	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
		// Ensure the room exists locally (stub it out if it's the first time seeing it)
		if _, err := s.canalRepo.GetByID(txCtx, roomID); err != nil {
			// Create room metadata locally if absent
			_, _ = s.canalRepo.Create(txCtx, roomID, protoEvent.Sender)
		}

		// Save the entire state block returned by the remote server
		for _, stateEv := range roomStateContext.StateEvents {
			if err := s.eventRepo.SaveEvento(txCtx, &stateEv); err != nil {
				return err
			}
			if stateEv.StateKey != nil {
				if err := s.canalRepo.UpsertCurrentState(txCtx, roomID, stateEv.Tipo, *stateEv.StateKey, stateEv.ID); err != nil {
					return err
				}
			}
		}

		// Save the join event itself
		if err := s.eventRepo.SaveEvento(txCtx, protoEvent); err != nil {
			return err
		}

		// Update your local DAG timeline extremities
		if err := s.canalRepo.UpdateForwardExtremities(txCtx, roomID, eventID, protoEvent.PrevEventos); err != nil {
			return err
		}

		// Update the room's current state for this user's membership slot
		if err := s.canalRepo.UpsertCurrentState(txCtx, roomID, "m.room.member", userID, eventID); err != nil {
			return err
		}

		// Finalize the fast-lookup membership state record
		if err := s.canalRepo.UpsertMembership(txCtx, roomID, userID, "join", eventID); err != nil {
			return err
		}

		return nil
	})

	return err
}
