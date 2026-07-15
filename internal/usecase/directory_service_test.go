package usecase

import (
	"context"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

type fakeCanalStore struct {
	joinedRooms []string
}

func (f *fakeCanalStore) Create(ctx context.Context, roomID, userID string) (*domain.Canal, error) {
	return nil, nil
}

func (f *fakeCanalStore) GetByID(ctx context.Context, canalID string) (*domain.Canal, error) {
	return nil, nil
}

func (f *fakeCanalStore) GetJoinRule(ctx context.Context, roomID string) (string, error) {
	return "", nil
}

func (f *fakeCanalStore) GetUserJoinedRooms(ctx context.Context, userID string) ([]string, error) {
	return f.joinedRooms, nil
}

func (f *fakeCanalStore) GetUserLeftRooms(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}

func (f *fakeCanalStore) GetUserMembership(ctx context.Context, roomID, userID string) (string, error) {
	return "", nil
}

func (f *fakeCanalStore) GetUserMembershipRecord(ctx context.Context, roomID, userID string) (string, bool, error) {
	return "", false, nil
}

func (f *fakeCanalStore) GetStateEventID(ctx context.Context, canalID string, stateType, stateKey string) (string, bool) {
	return "", false
}

func (f *fakeCanalStore) UpsertMembership(ctx context.Context, roomID, userID, membership, id_evento string) error {
	return nil
}

func (f *fakeCanalStore) UpsertCurrentState(ctx context.Context, canalID, stateType, stateKey, eventID string) error {
	return nil
}

func (f *fakeCanalStore) GetAllPublic(ctx context.Context, offset, limit int) ([]domain.Canal, error) {
	return nil, nil
}

func (f *fakeCanalStore) UpdateForwardExtremities(ctx context.Context, canalID string, eventID string, prevs []string) error {
	return nil
}

func (f *fakeCanalStore) GetForwardExtremities(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}

func (f *fakeCanalStore) SaveAlias(ctx context.Context, roomID, fullAlias string) error {
	return nil
}

func (f *fakeCanalStore) GetCanalParticipatingServers(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}

func TestDirectoryServiceSearchProfilesBuildsFilter(t *testing.T) {
	display := "Alice"
	avatar := "mxc://example.com/abc"
	userStore := &fakeUserStore{
		searchUsers: []domain.Profile{{IDUsuario: "@alice:example.com", DisplayName: &display, AvatarURL: &avatar}},
	}
	canalStore := &fakeCanalStore{joinedRooms: []string{"!room1:example.com", "!room2:example.com"}}

	svc := NewDirectoryService(nil, userStore, canalStore)

	ctx := context.WithValue(context.Background(), types.UserIDKey, "@searcher:example.com")
	profiles, err := svc.SearchProfiles(ctx, "Ali", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}

	if userStore.lastFilter.Term != "Ali" {
		t.Fatalf("expected search term to be passed")
	}
	if userStore.lastFilter.Limit != 11 {
		t.Fatalf("expected limit+1, got %d", userStore.lastFilter.Limit)
	}
	if len(userStore.lastFilter.IDCanais) != 2 {
		t.Fatalf("expected joined rooms to be used as filter")
	}
}

func TestDirectoryServiceSearchProfilesRequiresQuery(t *testing.T) {
	svc := NewDirectoryService(nil, &fakeUserStore{}, &fakeCanalStore{})
	ctx := context.WithValue(context.Background(), types.UserIDKey, "@searcher:example.com")

	_, err := svc.SearchProfiles(ctx, "", 10)
	if err != types.ErrInvalidSearchTerm {
		t.Fatalf("expected ErrInvalidSearchTerm, got %v", err)
	}
}
