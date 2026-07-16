package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type SyncService struct {
	userStore  UsuarioStorage
	eventStore EventoStorage
	canalStore CanalStorage
	notifier   Notifier
}

func NewSyncService(userStore UsuarioStorage, eventStore EventoStorage, canalStore CanalStorage, notifier Notifier) *SyncService {
	return &SyncService{
		userStore:  userStore,
		eventStore: eventStore,
		canalStore: canalStore,
		notifier:   notifier,
	}
}

type SyncAccountData struct {
	Events []domain.AccountData `json:"events"`
}

// Resposta GET /_matrix/client/v3/sync
type SyncClientResponse struct {
	AccountData SyncAccountData  `json:"account_data"`
	NextBatch   domain.SyncToken `json:"next_batch"`
	Rooms       RoomsSync        `json:"rooms"`
}

type RoomsSync struct {
	Invite map[string]InvitedRoom `json:"invite"`
	Join   map[string]JoinedRoom  `json:"join"`
	Leave  map[string]LeftRoom    `json:"leave"`
}

type InvitedRoom struct {
	InviteState InviteState `json:"invite_state"`
}

type InviteState struct {
	Events []domain.StrippedEvento `json:"events,omitempty"`
}

type JoinedRoom struct {
	AccountData []domain.AccountData `json:"account_data"`
	State       State                `json:"state"`
	Timeline    Timeline             `json:"timeline"`
}

type State struct {
	Events []EventoWithoutCanalID `json:"events,omitempty"`
}

type Timeline struct {
	Events    []EventoWithoutCanalID `json:"events,omitempty"`
	Limited   bool                   `json:"limited,omitempty"`
	PrevBatch domain.SyncToken       `json:"prev_batch"`
}

type EventoWithoutCanalID struct {
	ID               string          `json:"event_id"`
	Tipo             string          `json:"type"`
	Content          json.RawMessage `json:"content"`
	Sender           string          `json:"sender"`
	OrigemServidorTS int64           `json:"origin_server_ts"`

	StateKey *string `json:"state_key"`

	Unsigned json.RawMessage `json:"unsigned"` // dados adicionados pelo servidor
}

type LeftRoom struct {
	State    State    `json:"state"`
	Timeline Timeline `json:"timeline"`
}

func (s *SyncService) SyncClient(ctx context.Context, userID string, since domain.SyncToken, timeout time.Duration) (SyncClientResponse, error) {
	response, err := s.GetEventsSince(ctx, userID, since)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return SyncClientResponse{}, nil
		}

		return SyncClientResponse{
			NextBatch: since,
		}, err
	}

	// sem long-polling, envia eventos
	if !isResponseEmpty(response) || timeout <= 0 {
		nextBatch, err := s.generateNextSinceToken(ctx, userID, since)
		if err != nil {
			return SyncClientResponse{
				NextBatch: since,
			}, err
		}
		response.NextBatch = nextBatch
		return response, nil
	}

	// Long-polling.
	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// espera por uma notificação do banco
	err = s.notifier.WaitForEvents(pollCtx, userID)
	if err != nil {
		// deu timeout, retornamos apenas uma lista vazia.
		if errors.Is(err, context.DeadlineExceeded) {
			nextBatch, err := s.generateNextSinceToken(ctx, userID, since)
			if err != nil {
				return SyncClientResponse{
					NextBatch: since,
				}, err
			}

			response.NextBatch = nextBatch
			return response, nil
		}

		if errors.Is(err, context.Canceled) {
			return SyncClientResponse{}, nil
		}

		return SyncClientResponse{NextBatch: since}, err
	}

	response, err = s.GetEventsSince(ctx, userID, since)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return SyncClientResponse{}, nil
		}

		return SyncClientResponse{
			NextBatch: since,
		}, err
	}

	nextBatch, err := s.generateNextSinceToken(ctx, userID, since)
	if err != nil {
		return SyncClientResponse{
			NextBatch: since,
		}, err
	}
	response.NextBatch = nextBatch

	return response, nil
}

func (s *SyncService) generateNextSinceToken(ctx context.Context, userID string, since domain.SyncToken) (domain.SyncToken, error) {
	eventos, err := s.eventStore.GetSince(ctx, userID, since)
	if err != nil {
		return since, err
	}

	if len(eventos) > 0 {
		return util.GenerateNextSinceToken(since, eventos), nil
	}

	maxOrdering, err := s.eventStore.GetMaxStreamOrdering(ctx)
	if err != nil {
		return since, err
	}

	nextToken := since
	if maxOrdering > since.TimelinePosition {
		nextToken.TimelinePosition = maxOrdering
	}

	return nextToken, nil
}

func isResponseEmpty(response SyncClientResponse) bool {
	if len(response.Rooms.Invite) > 0 || len(response.Rooms.Leave) > 0 {
		return false
	}
	for _, room := range response.Rooms.Join {
		if len(room.Timeline.Events) > 0 || len(room.State.Events) > 0 {
			return false
		}
	}
	return true
}

func (s *SyncService) GetEventsSince(ctx context.Context, userID string, since domain.SyncToken) (SyncClientResponse, error) {
	accountData, err := s.userStore.GetGlobalAccountData(ctx, userID)
	if err != nil {
		return SyncClientResponse{
			NextBatch: since,
		}, err
	}

	mapInvites, err := s.GetInviteRooms(ctx, userID, since)
	if err != nil {
		return SyncClientResponse{
			AccountData: SyncAccountData{Events: accountData},
			NextBatch:   since,
		}, err
	}

	mapJoined, err := s.GetJoinedRooms(ctx, userID, since)
	if err != nil {
		return SyncClientResponse{
			AccountData: SyncAccountData{Events: accountData},
			NextBatch:   since,
		}, err
	}

	mapLeft, err := s.GetLeaveRooms(ctx, userID, since)
	if err != nil {
		return SyncClientResponse{
			AccountData: SyncAccountData{Events: accountData},
			NextBatch:   since,
		}, err
	}

	return SyncClientResponse{
		AccountData: SyncAccountData{Events: accountData},
		NextBatch:   since,
		Rooms: RoomsSync{
			Invite: mapInvites,
			Join:   mapJoined,
			Leave:  mapLeft,
		},
	}, nil
}

func (s *SyncService) GetInviteRooms(ctx context.Context, userID string, since domain.SyncToken) (map[string]InvitedRoom, error) {
	inviteEvents, err := s.userStore.GetInviteEventsSince(ctx, userID, since)
	if err != nil {
		return nil, err
	}

	mapInvites := make(map[string]InvitedRoom)
	for _, event := range inviteEvents {
		s := domain.StrippedEvento{
			Tipo:     event.Tipo,
			Content:  event.Content,
			StateKey: event.StateKey,
			Sender:   event.Sender,
		}
		room, exists := mapInvites[event.CanalID]
		if !exists {
			room = InvitedRoom{
				InviteState: InviteState{
					Events: []domain.StrippedEvento{},
				},
			}
		}
		room.InviteState.Events = append(room.InviteState.Events, s)
		mapInvites[event.CanalID] = room
	}
	return mapInvites, nil
}

func (s *SyncService) GetJoinedRooms(ctx context.Context, userID string, since domain.SyncToken) (map[string]JoinedRoom, error) {
	rooms, err := s.canalStore.GetUserJoinedRooms(ctx, userID)
	if err != nil {
		log.Printf("failed to get user joined rooms: %v", err)
		return nil, nil
	}

	if len(rooms) == 0 {
		return map[string]JoinedRoom{}, nil
	}

	mapJoined := make(map[string]JoinedRoom)

	isFirstSync := since.TimelinePosition == 0

	for _, roomID := range rooms {

		events, err := s.eventStore.GetEventsOfCanalSince(ctx, userID, roomID, since)
		if err != nil {
			log.Printf("failed to get events of canal %s: %v", roomID, err)
			continue
		}

		var stateEvents []EventoWithoutCanalID
		if isFirstSync {
			currState, err := s.eventStore.GetCurrentStateEvents(ctx, roomID)
			if err != nil {
				log.Printf("failed to get state events of canal %s: %v", roomID, err)
				continue
			}

			stateEvents = make([]EventoWithoutCanalID, len(currState))
			for i, event := range currState {
				stateEvents[i] = EventoWithoutCanalID{
					ID:               event.ID,
					Tipo:             event.Tipo,
					Content:          event.Content,
					StateKey:         event.StateKey,
					Sender:           event.Sender,
					OrigemServidorTS: event.OrigemServidorTS,
					Unsigned:         event.Unsigned,
				}
			}
		} else {
			// On incremental sync, ONLY send state events that occurred SINCE the sync token
			// We can filter our timeline events for state events (events that have a state_key)
			for _, event := range events {
				if event.StateKey != nil {
					stateEvents = append(stateEvents, EventoWithoutCanalID{
						ID:               event.ID,
						Tipo:             event.Tipo,
						Content:          event.Content,
						StateKey:         event.StateKey,
						Sender:           event.Sender,
						OrigemServidorTS: event.OrigemServidorTS,
						Unsigned:         event.Unsigned,
					})
				}
			}
		}
		accData, err := s.userStore.GetAccountDataOfCanal(ctx, userID, roomID)
		if err != nil {
			// skip this room on fail
			log.Printf("failed to get account data of canal %s: %v", roomID, err)
			continue
		}

		// IMPORTANT: skip if no new events during polling
		if !isFirstSync && len(events) == 0 && len(stateEvents) == 0 && len(accData) == 0 {
			continue
		}

		parsedEvents := make([]EventoWithoutCanalID, len(events))
		for i, event := range events {
			parsedEvents[i] = EventoWithoutCanalID{
				ID:               event.ID,
				Tipo:             event.Tipo,
				Content:          event.Content,
				StateKey:         event.StateKey,
				OrigemServidorTS: event.OrigemServidorTS,
				Sender:           event.Sender,
				Unsigned:         event.Unsigned,
			}
		}

		// DYNAMIC PREV_BATCH CALCULATION:
		// If we returned events, the prev_batch should point to the stream ordering of
		// the EARLIEST event in our slice (events[0]) so that scrolling back starts right before it.
		// If we returned no events, we fall back to the query's 'since' token.
		prevBatchToken := since
		if len(events) > 0 {
			// Subtract 1 from the earliest stream_ordering to represent the boundary just before it
			prevBatchToken.TimelinePosition = max(events[0].StreamOrdering-1, 0)
		}

		mapJoined[roomID] = JoinedRoom{
			AccountData: accData,
			State:       State{Events: stateEvents},
			Timeline: Timeline{
				Events:    parsedEvents,
				Limited:   false,
				PrevBatch: prevBatchToken,
			},
		}
	}

	return mapJoined, nil
}

func (s *SyncService) GetLeaveRooms(ctx context.Context, userID string, since domain.SyncToken) (map[string]LeftRoom, error) {
	leftRooms, err := s.canalStore.GetUserLeftRooms(ctx, userID)
	if err != nil {
		log.Printf("failed to get user left rooms: %v", err)
		return nil, nil
	}

	if len(leftRooms) == 0 {
		return map[string]LeftRoom{}, nil
	}

	mapLeft := make(map[string]LeftRoom)
	isInitialSync := since.TimelinePosition == 0

	for _, roomID := range leftRooms {
		events, err := s.eventStore.GetEventsOfCanalSinceLeft(ctx, userID, roomID, since)
		if err != nil {
			log.Printf("failed to get events of canal %s: %v", roomID, err)
			continue
		}

		var stateEvents []EventoWithoutCanalID
		if isInitialSync {
			currState, err := s.eventStore.GetCurrentStateEvents(ctx, roomID)
			if err != nil {
				log.Printf("failed to get state events of canal %s: %v", roomID, err)
				continue
			}
			stateEvents = make([]EventoWithoutCanalID, len(currState))
			for i, event := range currState {
				stateEvents[i] = EventoWithoutCanalID{
					ID:               event.ID,
					Tipo:             event.Tipo,
					Content:          event.Content,
					StateKey:         event.StateKey,
					Sender:           event.Sender,
					OrigemServidorTS: event.OrigemServidorTS,
					Unsigned:         event.Unsigned,
				}
			}
		} else {
			for _, event := range events {
				if event.StateKey != nil {
					stateEvents = append(stateEvents, EventoWithoutCanalID{
						ID:               event.ID,
						Tipo:             event.Tipo,
						Content:          event.Content,
						StateKey:         event.StateKey,
						Sender:           event.Sender,
						OrigemServidorTS: event.OrigemServidorTS,
						Unsigned:         event.Unsigned,
					})
				}
			}
		}

		// If no changes occurred on this room since the token, skip it
		if !isInitialSync && len(events) == 0 && len(stateEvents) == 0 {
			continue
		}

		parsedEvents := make([]EventoWithoutCanalID, len(events))
		for i, event := range events {
			parsedEvents[i] = EventoWithoutCanalID{
				ID:               event.ID,
				Tipo:             event.Tipo,
				Content:          event.Content,
				StateKey:         event.StateKey,
				OrigemServidorTS: event.OrigemServidorTS,
				Sender:           event.Sender,
				Unsigned:         event.Unsigned,
			}
		}

		prevBatchToken := since
		if len(events) > 0 {
			prevBatchToken.TimelinePosition = max(events[0].StreamOrdering-1, 0)
		}

		mapLeft[roomID] = LeftRoom{
			State: State{Events: stateEvents},
			Timeline: Timeline{
				Events:    parsedEvents,
				Limited:   false,
				PrevBatch: prevBatchToken, // <-- Corrected
			},
		}
	}

	return mapLeft, nil
}
