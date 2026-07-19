package usecase

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

type MockFederationCacheStorage struct {
}

func (m *MockFederationCacheStorage) SavePendingRetry(ctx context.Context, destServer string, event *domain.Evento, ttl time.Duration) error {
	return m.SavePendingRetry(ctx, destServer, event, ttl)
}

func (m *MockFederationCacheStorage) GetAndClearPendingRetries(ctx context.Context, destServer string) ([]domain.Evento, error) {
	return m.GetAndClearPendingRetries(ctx, destServer)
}

func (m *MockFederationCacheStorage) PushOutboundQueue(ctx context.Context, event domain.Evento) error {
	return m.PushOutboundQueue(ctx, event)
}

func (m *MockFederationCacheStorage) PopOutboundQueue(ctx context.Context, timeout time.Duration) (*domain.Evento, error) {
	return m.PopOutboundQueue(ctx, timeout)
}

func newTestRoomInteractionService(t *testing.T, canal *roomsvcFakeCanalStorage, evento *roomsvcFakeEventoStorage, fedCache *MockFederationCacheStorage) *RoomInteractionService {
	t.Helper()
	uow := &roomsvcFakeWorkUnit{}
	authResolver := NewAuthRuleResolver(canal)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	fedSvc := NewFederationService("example.com", "ed25519:1", priv, canal, evento, uow, nil, nil, fedCache)
	return NewRoomInteractionService(canal, evento, fedSvc, authResolver, uow, "example.com", "ed25519:1", priv)
}

// SendStateEvent

func TestSendStateEvent_Forbidden(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	svc := newTestRoomInteractionService(t, newRoomsvcFakeCanalStorage(), newRoomsvcFakeEventoStorage(), &MockFederationCacheStorage{})

	_, err := svc.SendStateEvent(context.Background(), StateParams{
		RoomID: roomID, UserID: userID, EventType: "m.room.topic", Content: map[string]any{"topic": "hi"},
	})
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestSendStateEvent_Success(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomInteractionService(t, canal, evento, &MockFederationCacheStorage{})

	eventID, err := svc.SendStateEvent(context.Background(), StateParams{
		RoomID: roomID, UserID: userID, EventType: "m.room.topic", Content: map[string]any{"topic": "hi"},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if eventID == "" {
		t.Error("expected non-empty event id")
	}
	if len(evento.saved) != 1 {
		t.Fatalf("expected 1 saved event, got %d", len(evento.saved))
	}
	if len(canal.upsertedState) != 1 || canal.upsertedState[0].StateType != "m.room.topic" {
		t.Errorf("expected 1 upserted state of type m.room.topic, got %+v", canal.upsertedState)
	}
}

// SendEvent

func TestSendEvent_Forbidden(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	svc := newTestRoomInteractionService(t, newRoomsvcFakeCanalStorage(), newRoomsvcFakeEventoStorage(), &MockFederationCacheStorage{})

	_, err := svc.SendEvent(context.Background(), EventParams{
		RoomID: roomID, SenderID: userID, EventType: "m.room.message", Content: map[string]any{"body": "oi"},
	})
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestSendEvent_Success(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomInteractionService(t, canal, evento, &MockFederationCacheStorage{})

	eventID, err := svc.SendEvent(context.Background(), EventParams{
		RoomID: roomID, SenderID: userID, EventType: "m.room.message", Content: map[string]any{"body": "oi"},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if eventID == "" {
		t.Error("expected non-empty event id")
	}
	if len(evento.saved) != 1 {
		t.Fatalf("expected 1 saved event, got %d", len(evento.saved))
	}
	if evento.saved[0].StateKey != nil {
		t.Error("expected regular event to have nil state_key")
	}
}

// SendReceipt

func TestSendReceipt_Forbidden(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	svc := newTestRoomInteractionService(t, newRoomsvcFakeCanalStorage(), newRoomsvcFakeEventoStorage(), &MockFederationCacheStorage{})

	err := svc.SendReceipt(context.Background(), userID, roomID, "m.read", "$event1")
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestSendReceipt_Success(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	svc := newTestRoomInteractionService(t, canal, newRoomsvcFakeEventoStorage(), &MockFederationCacheStorage{})

	if err := svc.SendReceipt(context.Background(), userID, roomID, "m.read", "$event1"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// GetMessages

func TestGetMessages_Forbidden(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	svc := newTestRoomInteractionService(t, newRoomsvcFakeCanalStorage(), newRoomsvcFakeEventoStorage(), &MockFederationCacheStorage{})

	_, err := svc.GetMessages(context.Background(), roomID, userID, "", "b", 10)
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestGetMessages_Success(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	evento := newRoomsvcFakeEventoStorage()
	evento.messagesHistory = []domain.Evento{
		{ID: "$1", Tipo: "m.room.message", StreamOrdering: 10},
		{ID: "$2", Tipo: "m.room.message", StreamOrdering: 20},
	}
	svc := newTestRoomInteractionService(t, canal, evento, &MockFederationCacheStorage{})

	resp, err := svc.GetMessages(context.Background(), roomID, userID, "0", "b", 10)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(resp.Chunk) != 2 {
		t.Fatalf("expected 2 events in chunk, got %d", len(resp.Chunk))
	}
	if resp.End != "s20_0_0" {
		t.Errorf("expected end token 's20_0_0', got %q", resp.End)
	}
}

func TestGetMessages_SetsStartWhenFromMissing(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	evento := newRoomsvcFakeEventoStorage()
	evento.messagesHistory = []domain.Evento{
		{ID: "$3", Tipo: "m.room.message", StreamOrdering: 30},
		{ID: "$2", Tipo: "m.room.message", StreamOrdering: 20},
	}
	svc := newTestRoomInteractionService(t, canal, evento, &MockFederationCacheStorage{})

	resp, err := svc.GetMessages(context.Background(), roomID, userID, "", "b", 10)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Start != "s30_0_0" {
		t.Fatalf("expected start token 's30_0_0', got %q", resp.Start)
	}
	if resp.End != "s20_0_0" {
		t.Fatalf("expected end token 's20_0_0', got %q", resp.End)
	}
}

func TestGetMessages_InvalidDirection(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	svc := newTestRoomInteractionService(t, canal, newRoomsvcFakeEventoStorage(), &MockFederationCacheStorage{})

	_, err := svc.GetMessages(context.Background(), roomID, userID, "", "x", 10)
	if !errors.Is(err, ErrInvalidPaginationDirection) {
		t.Fatalf("expected ErrInvalidPaginationDirection, got %v", err)
	}
}

//  GetStateEventContent

func TestGetStateEventContent_NeverAMember(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	svc := newTestRoomInteractionService(t, newRoomsvcFakeCanalStorage(), newRoomsvcFakeEventoStorage(), &MockFederationCacheStorage{})

	_, err := svc.GetStateEventContent(context.Background(), roomID, userID, "m.room.topic", "")
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestGetStateEventContent_Banned(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "ban"
	svc := newTestRoomInteractionService(t, canal, newRoomsvcFakeEventoStorage(), &MockFederationCacheStorage{})

	_, err := svc.GetStateEventContent(context.Background(), roomID, userID, "m.room.topic", "")
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestGetStateEventContent_StateNotFound(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	svc := newTestRoomInteractionService(t, canal, newRoomsvcFakeEventoStorage(), &MockFederationCacheStorage{})

	_, err := svc.GetStateEventContent(context.Background(), roomID, userID, "m.room.topic", "")
	if !errors.Is(err, ErrStateNotFound) {
		t.Errorf("expected ErrStateNotFound, got %v", err)
	}
}

func TestGetStateEventContent_Success(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	canal.stateEventIDs[roomsvcStateKey(roomID, "m.room.topic", "")] = "$topic1"

	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomInteractionService(t, canal, evento, &MockFederationCacheStorage{})
	evento.events["$topic1"] = domain.Evento{ID: "$topic1", Tipo: "m.room.topic", Content: json.RawMessage(`{"topic":"Bem-vindo"}`)}

	ev, err := svc.GetStateEventContent(context.Background(), roomID, userID, "m.room.topic", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ev.ID != "$topic1" {
		t.Errorf("expected event $topic1, got %s", ev.ID)
	}
}

func TestGetStateEventContent_AllowedAfterLeaving(t *testing.T) {
	// Comportamento atual: um ex-membro (status "leave") ainda pode ler o estado
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "leave"
	canal.stateEventIDs[roomsvcStateKey(roomID, "m.room.topic", "")] = "$topic1"

	evento := newRoomsvcFakeEventoStorage()
	evento.events["$topic1"] = domain.Evento{ID: "$topic1", Tipo: "m.room.topic", Content: json.RawMessage(`{"topic":"x"}`)}
	svc := newTestRoomInteractionService(t, canal, evento, &MockFederationCacheStorage{})

	if _, err := svc.GetStateEventContent(context.Background(), roomID, userID, "m.room.topic", ""); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
