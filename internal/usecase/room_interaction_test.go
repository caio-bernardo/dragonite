package usecase

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

func newTestRoomInteractionService(t *testing.T, canal *roomsvcFakeCanalStorage, evento *roomsvcFakeEventoStorage) *RoomInteractionService {
	t.Helper()
	uow := &roomsvcFakeWorkUnit{}
	authResolver := NewAuthRuleResolver(canal)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	fedSvc := NewFederationService("example.com", "ed25519:1", priv, canal, evento, uow, nil)
	return NewRoomInteractionService(canal, evento, fedSvc, authResolver, uow, "example.com", "ed25519:1", priv)
}

// SendStateEvent 

func TestSendStateEvent_Forbidden(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	svc := newTestRoomInteractionService(t, newRoomsvcFakeCanalStorage(), newRoomsvcFakeEventoStorage())

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
	svc := newTestRoomInteractionService(t, canal, evento)

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

	svc := newTestRoomInteractionService(t, newRoomsvcFakeCanalStorage(), newRoomsvcFakeEventoStorage())

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
	svc := newTestRoomInteractionService(t, canal, evento)

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

	svc := newTestRoomInteractionService(t, newRoomsvcFakeCanalStorage(), newRoomsvcFakeEventoStorage())

	err := svc.SendReceipt(context.Background(), userID, roomID, "m.read", "$event1")
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestSendReceipt_Success(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	svc := newTestRoomInteractionService(t, canal, newRoomsvcFakeEventoStorage())

	if err := svc.SendReceipt(context.Background(), userID, roomID, "m.read", "$event1"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// GetMessages

func TestGetMessages_Forbidden(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	svc := newTestRoomInteractionService(t, newRoomsvcFakeCanalStorage(), newRoomsvcFakeEventoStorage())

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
	svc := newTestRoomInteractionService(t, canal, evento)

	resp, err := svc.GetMessages(context.Background(), roomID, userID, "0", "b", 10)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(resp.Chunk) != 2 {
		t.Fatalf("expected 2 events in chunk, got %d", len(resp.Chunk))
	}
	if resp.End != "20" {
		t.Errorf("expected end token '20', got %q", resp.End)
	}
}

//  GetStateEventContent 

func TestGetStateEventContent_NeverAMember(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	svc := newTestRoomInteractionService(t, newRoomsvcFakeCanalStorage(), newRoomsvcFakeEventoStorage())

	_, err := svc.GetStateEventContent(context.Background(), roomID, userID, "m.room.topic", "")
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestGetStateEventContent_Banned(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "ban"
	svc := newTestRoomInteractionService(t, canal, newRoomsvcFakeEventoStorage())

	_, err := svc.GetStateEventContent(context.Background(), roomID, userID, "m.room.topic", "")
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestGetStateEventContent_StateNotFound(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	svc := newTestRoomInteractionService(t, canal, newRoomsvcFakeEventoStorage())

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
	evento.events["$topic1"] = domain.Evento{ID: "$topic1", Tipo: "m.room.topic", Content: json.RawMessage(`{"topic":"Bem-vindo"}`)}
	svc := newTestRoomInteractionService(t, canal, evento)

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
	svc := newTestRoomInteractionService(t, canal, evento)

	if _, err := svc.GetStateEventContent(context.Background(), roomID, userID, "m.room.topic", ""); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}