package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

// Fakes

type presencesvcFakeCanalStorage struct {
	joinedRooms map[string][]string // userID -> room IDs
}

func newPresencesvcFakeCanalStorage() *presencesvcFakeCanalStorage {
	return &presencesvcFakeCanalStorage{joinedRooms: make(map[string][]string)}
}

func (f *presencesvcFakeCanalStorage) Create(ctx context.Context, roomID, userID string) (*domain.Canal, error) {
	return nil, nil
}
func (f *presencesvcFakeCanalStorage) GetCanalParticipatingServers(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}
func (f *presencesvcFakeCanalStorage) GetByID(ctx context.Context, canalID string) (*domain.Canal, error) {
	return nil, nil
}
func (f *presencesvcFakeCanalStorage) GetJoinRule(ctx context.Context, roomID string) (string, error) {
	return "", nil
}
func (f *presencesvcFakeCanalStorage) GetUserJoinedRooms(ctx context.Context, userID string) ([]string, error) {
	return f.joinedRooms[userID], nil
}
func (f *presencesvcFakeCanalStorage) GetUserLeftRooms(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}
func (f *presencesvcFakeCanalStorage) GetUserMembership(ctx context.Context, roomID, userID string) (string, error) {
	return "", nil
}
func (f *presencesvcFakeCanalStorage) GetUserMembershipRecord(ctx context.Context, roomID, userID string) (string, bool, error) {
	return "", false, nil
}
func (f *presencesvcFakeCanalStorage) GetStateEventID(ctx context.Context, canalID string, stateType, stateKey string) (string, bool) {
	return "", false
}
func (f *presencesvcFakeCanalStorage) UpsertMembership(ctx context.Context, roomID, userID, membership, id_evento string) error {
	return nil
}
func (f *presencesvcFakeCanalStorage) UpsertCurrentState(ctx context.Context, canalID, stateType, stateKey, eventID string) error {
	return nil
}
func (f *presencesvcFakeCanalStorage) GetAllPublic(ctx context.Context, offset, limit int) ([]domain.Canal, error) {
	return nil, nil
}
func (f *presencesvcFakeCanalStorage) UpdateForwardExtremities(ctx context.Context, canalID string, newEventID string, prevEvents []string) error {
	return nil
}
func (f *presencesvcFakeCanalStorage) GetForwardExtremities(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}
func (f *presencesvcFakeCanalStorage) SaveAlias(ctx context.Context, roomID, fullAlias string) error {
	return nil
}

type presencesvcFakePresenceStorage struct {
	data      map[string]domain.Presence
	upsertErr error
	getErr    error
}

func newPresencesvcFakePresenceStorage() *presencesvcFakePresenceStorage {
	return &presencesvcFakePresenceStorage{data: make(map[string]domain.Presence)}
}

func (f *presencesvcFakePresenceStorage) UpsertPresence(ctx context.Context, presence domain.Presence) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.data[presence.IDUsuario] = presence
	return nil
}

func (f *presencesvcFakePresenceStorage) GetPresence(ctx context.Context, userID string) (*domain.Presence, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	p, ok := f.data[userID]
	if !ok {
		return nil, nil
	}
	return &p, nil
}

// Testes de SetStatus

func TestPresenceServiceSetStatus_Success(t *testing.T) {
	presenceStore := newPresencesvcFakePresenceStorage()
	svc := NewPresenceService(presenceStore, newPresencesvcFakeCanalStorage())

	msg := "Fazendo cupcakes"
	err := svc.SetStatus(context.Background(), "@alice:example.com", domain.PresenceOnline, &msg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	saved := presenceStore.data["@alice:example.com"]
	if saved.State != domain.PresenceOnline {
		t.Errorf("expected state online, got %s", saved.State)
	}
	if saved.StatusMsg == nil || *saved.StatusMsg != msg {
		t.Errorf("expected status_msg %q, got %v", msg, saved.StatusMsg)
	}
	if saved.LastActiveAt.IsZero() {
		t.Error("expected LastActiveAt to be set")
	}
}

func TestPresenceServiceSetStatus_InvalidState(t *testing.T) {
	svc := NewPresenceService(newPresencesvcFakePresenceStorage(), newPresencesvcFakeCanalStorage())

	err := svc.SetStatus(context.Background(), "@alice:example.com", domain.PresenceState("dormindo"), nil)
	if !errors.Is(err, types.ErrInvalidParam) {
		t.Fatalf("expected types.ErrInvalidParam, got %v", err)
	}
}

// Testes de GetStatus

func TestPresenceServiceGetStatus_Self(t *testing.T) {
	presenceStore := newPresencesvcFakePresenceStorage()
	presenceStore.data["@alice:example.com"] = domain.Presence{IDUsuario: "@alice:example.com", State: domain.PresenceOnline}
	svc := NewPresenceService(presenceStore, newPresencesvcFakeCanalStorage())

	presence, err := svc.GetStatus(context.Background(), "@alice:example.com", "@alice:example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if presence.State != domain.PresenceOnline {
		t.Errorf("expected state online, got %s", presence.State)
	}
}

func TestPresenceServiceGetStatus_SharedRoomAllowed(t *testing.T) {
	canalStore := newPresencesvcFakeCanalStorage()
	canalStore.joinedRooms["@alice:example.com"] = []string{"!room1:example.com"}
	canalStore.joinedRooms["@bob:example.com"] = []string{"!room1:example.com", "!room2:example.com"}
	presenceStore := newPresencesvcFakePresenceStorage()
	presenceStore.data["@bob:example.com"] = domain.Presence{IDUsuario: "@bob:example.com", State: domain.PresenceUnavailable}
	svc := NewPresenceService(presenceStore, canalStore)

	presence, err := svc.GetStatus(context.Background(), "@alice:example.com", "@bob:example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if presence.State != domain.PresenceUnavailable {
		t.Errorf("expected state unavailable, got %s", presence.State)
	}
}

func TestPresenceServiceGetStatus_NoSharedRoomForbidden(t *testing.T) {
	canalStore := newPresencesvcFakeCanalStorage()
	canalStore.joinedRooms["@alice:example.com"] = []string{"!room1:example.com"}
	canalStore.joinedRooms["@bob:example.com"] = []string{"!room2:example.com"}
	presenceStore := newPresencesvcFakePresenceStorage()
	presenceStore.data["@bob:example.com"] = domain.Presence{IDUsuario: "@bob:example.com", State: domain.PresenceOnline}
	svc := NewPresenceService(presenceStore, canalStore)

	_, err := svc.GetStatus(context.Background(), "@alice:example.com", "@bob:example.com")
	if !errors.Is(err, types.ErrForbidden) {
		t.Fatalf("expected types.ErrForbidden, got %v", err)
	}
}

func TestPresenceServiceGetStatus_NotFound(t *testing.T) {
	svc := NewPresenceService(newPresencesvcFakePresenceStorage(), newPresencesvcFakeCanalStorage())

	_, err := svc.GetStatus(context.Background(), "@alice:example.com", "@alice:example.com")
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected types.ErrNotFound, got %v", err)
	}
}