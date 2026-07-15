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

func newTestRoomMembershipService(t *testing.T, canal *roomsvcFakeCanalStorage, evento *roomsvcFakeEventoStorage) *RoomMembershipService {
	t.Helper()
	uow := &roomsvcFakeWorkUnit{}
	authResolver := NewAuthRuleResolver(canal)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	fedSvc := NewFederationService("example.com", "ed25519:1", priv, canal, evento, uow, nil)
	return NewRoomMembershipService(uow, canal, evento, authResolver, fedSvc, nil)
}

//  InviteUser 

func TestInviteUser_Success(t *testing.T) {
	roomID, inviter, invitee := "!room1:example.com", "@alice:example.com", "@bob:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, inviter)] = "join"
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	if err := svc.InviteUser(context.Background(), roomID, inviter, invitee, "Welcome to the team!"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(canal.upsertedMemberships) != 1 {
		t.Fatalf("expected 1 upserted membership, got %d", len(canal.upsertedMemberships))
	}
	got := canal.upsertedMemberships[0]
	if got.UserID != invitee || got.Membership != "invite" {
		t.Errorf("expected invitee %s with membership 'invite', got %+v", invitee, got)
	}

	if len(evento.saved) != 1 {
		t.Fatalf("expected 1 saved event, got %d", len(evento.saved))
	}
	saved := evento.saved[0]
	if saved.Tipo != "m.room.member" {
		t.Errorf("expected type m.room.member, got %s", saved.Tipo)
	}
	if saved.StateKey == nil || *saved.StateKey != invitee {
		t.Errorf("expected state_key %s, got %v", invitee, saved.StateKey)
	}

	var content map[string]any
	if err := json.Unmarshal(saved.Content, &content); err != nil {
		t.Fatalf("decode content: %v", err)
	}
	if content["membership"] != "invite" {
		t.Errorf("expected content.membership=invite, got %v", content["membership"])
	}
	if content["reason"] != "Welcome to the team!" {
		t.Errorf("expected content.reason preserved, got %v", content["reason"])
	}
}

func TestInviteUser_InviterNotInRoom(t *testing.T) {
	roomID, inviter, invitee := "!room1:example.com", "@alice:example.com", "@bob:example.com"

	canal := newRoomsvcFakeCanalStorage() // inviter nunca entrou -> "leave" por padrão
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	err := svc.InviteUser(context.Background(), roomID, inviter, invitee, "")
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
	if len(canal.upsertedMemberships) != 0 {
		t.Errorf("expected no membership upserted, got %+v", canal.upsertedMemberships)
	}
}

func TestInviteUser_InviteeBanned(t *testing.T) {
	roomID, inviter, invitee := "!room1:example.com", "@alice:example.com", "@bob:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, inviter)] = "join"
	canal.membership[roomsvcMembershipKey(roomID, invitee)] = "ban"
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	err := svc.InviteUser(context.Background(), roomID, inviter, invitee, "")
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestInviteUser_InviteeAlreadyJoined(t *testing.T) {
	roomID, inviter, invitee := "!room1:example.com", "@alice:example.com", "@bob:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, inviter)] = "join"
	canal.membership[roomsvcMembershipKey(roomID, invitee)] = "join"
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	err := svc.InviteUser(context.Background(), roomID, inviter, invitee, "")
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
}

func TestInviteUser_InsufficientPowerLevel(t *testing.T) {
	roomID, inviter, invitee := "!room1:example.com", "@alice:example.com", "@bob:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, inviter)] = "join"
	canal.stateEventIDs[roomsvcStateKey(roomID, "m.room.power_levels", "")] = "pl-1"

	evento := newRoomsvcFakeEventoStorage()
	evento.events["pl-1"] = domain.Evento{
		ID: "pl-1", Tipo: "m.room.power_levels",
		Content: json.RawMessage(`{"invite":50,"users_default":0,"users":{}}`),
	}

	svc := newTestRoomMembershipService(t, canal, evento)

	err := svc.InviteUser(context.Background(), roomID, inviter, invitee, "")
	if !errors.Is(err, types.ErrForbidden) {
		t.Errorf("expected types.ErrForbidden, got %v", err)
	}
	if len(canal.upsertedMemberships) != 0 {
		t.Errorf("expected no membership upserted, got %+v", canal.upsertedMemberships)
	}
}

func TestInviteUser_SufficientPowerLevel(t *testing.T) {
	roomID, inviter, invitee := "!room1:example.com", "@alice:example.com", "@bob:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, inviter)] = "join"
	canal.stateEventIDs[roomsvcStateKey(roomID, "m.room.power_levels", "")] = "pl-1"

	evento := newRoomsvcFakeEventoStorage()
	evento.events["pl-1"] = domain.Evento{
		ID: "pl-1", Tipo: "m.room.power_levels",
		Content: json.RawMessage(`{"invite":50,"users_default":0,"users":{"` + inviter + `":100}}`),
	}

	svc := newTestRoomMembershipService(t, canal, evento)

	if err := svc.InviteUser(context.Background(), roomID, inviter, invitee, ""); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestInviteUser_NoPowerLevelsDefined(t *testing.T) {
	// Sem m.room.power_levels na sala: a spec usa os defaults (invite=0), sempre permitido
	roomID, inviter, invitee := "!room1:example.com", "@alice:example.com", "@bob:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, inviter)] = "join"
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	if err := svc.InviteUser(context.Background(), roomID, inviter, invitee, ""); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

//  JoinLocalRoom 

func TestJoinLocalRoom_PublicRoom(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.joinRule = "public"
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	if err := svc.JoinLocalRoom(context.Background(), userID, roomID); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got := canal.membership[roomsvcMembershipKey(roomID, userID)]; got != "join" {
		t.Errorf("expected membership 'join', got %q", got)
	}
}

func TestJoinLocalRoom_InviteOnlyWithoutInvite(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.joinRule = "invite"
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	if err := svc.JoinLocalRoom(context.Background(), userID, roomID); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestJoinLocalRoom_InviteOnlyWithInvite(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.joinRule = "invite"
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "invite"
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	if err := svc.JoinLocalRoom(context.Background(), userID, roomID); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got := canal.membership[roomsvcMembershipKey(roomID, userID)]; got != "join" {
		t.Errorf("expected membership 'join', got %q", got)
	}
}

// LeaveRoom 

func TestLeaveRoom_Success(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	canal.membership[roomsvcMembershipKey(roomID, userID)] = "join"
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	if err := svc.LeaveRoom(context.Background(), userID, roomID); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got := canal.membership[roomsvcMembershipKey(roomID, userID)]; got != "leave" {
		t.Errorf("expected membership 'leave', got %q", got)
	}
}

func TestLeaveRoom_NotAMember(t *testing.T) {
	roomID, userID := "!room1:example.com", "@alice:example.com"

	canal := newRoomsvcFakeCanalStorage()
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	if err := svc.LeaveRoom(context.Background(), userID, roomID); err == nil {
		t.Fatal("expected error, got nil")
	}
}

//  GetJoinedRooms

func TestGetJoinedRooms_Empty(t *testing.T) {
	canal := newRoomsvcFakeCanalStorage()
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	rooms, err := svc.GetJoinedRooms(context.Background(), "@alice:example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if rooms == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(rooms) != 0 {
		t.Errorf("expected 0 rooms, got %d", len(rooms))
	}
}

func TestGetJoinedRooms_WithRooms(t *testing.T) {
	canal := newRoomsvcFakeCanalStorage()
	canal.joinedRooms = []string{"!room1:example.com", "!room2:example.com"}
	evento := newRoomsvcFakeEventoStorage()
	svc := newTestRoomMembershipService(t, canal, evento)

	rooms, err := svc.GetJoinedRooms(context.Background(), "@alice:example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(rooms) != 2 {
		t.Errorf("expected 2 rooms, got %d", len(rooms))
	}
}