package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/domain"
)

type fakeBackupStorage struct {
	created           *domain.VersaoBackup
	createErr         error
	nextID            int64
	getResult         *domain.VersaoBackup
	getErr            error
	versionsByID      map[int64]*domain.VersaoBackup
	keysByVersion     map[int64][]domain.ChaveBackup
	getRoomKeysErr    error
	putRoomKeysErr    error
	deleteRoomKeysErr error
}

// GET/POST /_matrix/client/v3/room_keys/version

func (f *fakeBackupStorage) CreateBackupVersion(ctx context.Context, backup *domain.VersaoBackup) error {
	if f.createErr != nil {
		return f.createErr
	}
	if f.nextID == 0 {
		f.nextID = 1
	}
	backup.IDVersao = f.nextID
	f.created = backup
	return nil
}

func (f *fakeBackupStorage) GetLatestBackupVersion(ctx context.Context, userID string) (*domain.VersaoBackup, error) {
	return f.getResult, f.getErr
}

func TestBackupServiceCreateBackupVersionSuccess(t *testing.T) {
	store := &fakeBackupStorage{nextID: 3}
	svc := NewBackupService(&roomsvcFakeWorkUnit{}, store)

	authData := json.RawMessage(`{"public_key":"abcdefg"}`)
	result, err := svc.CreateBackupVersion(context.Background(), CreateBackupParams{
		UserID:    "@alice:example.com",
		Algorithm: "m.megolm_backup.v1.curve25519-aes-sha2",
		AuthData:  authData,
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.VersionString() != "3" {
		t.Fatalf("expected version '3', got %s", result.VersionString())
	}
	if store.created == nil {
		t.Fatal("expected backup to be persisted")
	}
	if store.created.IDUsuario != "@alice:example.com" {
		t.Fatalf("expected id_usuario '@alice:example.com', got %s", store.created.IDUsuario)
	}
	if store.created.Count != 0 {
		t.Fatalf("expected initial count 0, got %d", store.created.Count)
	}
	if store.created.ETag != "0" {
		t.Fatalf("expected initial etag '0', got %s", store.created.ETag)
	}
}

func TestBackupServiceCreateBackupVersionStorageError(t *testing.T) {
	store := &fakeBackupStorage{createErr: errors.New("db connection lost")}
	svc := NewBackupService(&roomsvcFakeWorkUnit{}, store)

	_, err := svc.CreateBackupVersion(context.Background(), CreateBackupParams{
		UserID:    "@alice:example.com",
		Algorithm: "m.megolm_backup.v1.curve25519-aes-sha2",
		AuthData:  json.RawMessage(`{}`),
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestBackupServiceGetLatestBackupVersionSuccess(t *testing.T) {
	existing := &domain.VersaoBackup{
		IDVersao:  5,
		IDUsuario: "@alice:example.com",
		Algorithm: "m.megolm_backup.v1.curve25519-aes-sha2",
		AuthData:  json.RawMessage(`{"public_key":"abcdefg"}`),
		Count:     42,
		ETag:      "anopaquestring",
	}
	store := &fakeBackupStorage{getResult: existing}
	svc := NewBackupService(&roomsvcFakeWorkUnit{}, store)

	result, err := svc.GetLatestBackupVersion(context.Background(), "@alice:example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.VersionString() != "5" {
		t.Fatalf("expected version '5', got %s", result.VersionString())
	}
	if result.Count != 42 {
		t.Fatalf("expected count 42, got %d", result.Count)
	}
}

func TestBackupServiceGetLatestBackupVersionNotFound(t *testing.T) {
	store := &fakeBackupStorage{getResult: nil}
	svc := NewBackupService(&roomsvcFakeWorkUnit{}, store)

	_, err := svc.GetLatestBackupVersion(context.Background(), "@alice:example.com")
	if !errors.Is(err, ErrBackupNotFound) {
		t.Fatalf("expected ErrBackupNotFound, got %v", err)
	}
}

func TestBackupServiceGetLatestBackupVersionStorageError(t *testing.T) {
	store := &fakeBackupStorage{getErr: errors.New("db timeout")}
	svc := NewBackupService(&roomsvcFakeWorkUnit{}, store)

	_, err := svc.GetLatestBackupVersion(context.Background(), "@alice:example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrBackupNotFound) {
		t.Fatal("expected a generic error, not ErrBackupNotFound, when storage fails")
	}
}

// GET/PUT/DELETE /_matrix/client/v3/room_keys/keys

func (f *fakeBackupStorage) GetBackupVersionByID(ctx context.Context, userID string, versionID int64) (*domain.VersaoBackup, error) {
	b, ok := f.versionsByID[versionID]
	if !ok || b.IDUsuario != userID {
		return nil, nil
	}
	return b, nil
}

func (f *fakeBackupStorage) GetRoomKeys(ctx context.Context, versionID int64) ([]domain.ChaveBackup, error) {
	if f.getRoomKeysErr != nil {
		return nil, f.getRoomKeysErr
	}
	return f.keysByVersion[versionID], nil
}

func (f *fakeBackupStorage) PutRoomKeys(ctx context.Context, versionID int64, keys []domain.ChaveBackup) (int64, string, error) {
	if f.putRoomKeysErr != nil {
		return 0, "", f.putRoomKeysErr
	}
	if f.keysByVersion == nil {
		f.keysByVersion = make(map[int64][]domain.ChaveBackup)
	}
	f.keysByVersion[versionID] = append(f.keysByVersion[versionID], keys...)
	return int64(len(f.keysByVersion[versionID])), "1", nil
}

func (f *fakeBackupStorage) DeleteRoomKeys(ctx context.Context, versionID int64) (int64, string, error) {
	if f.deleteRoomKeysErr != nil {
		return 0, "", f.deleteRoomKeysErr
	}
	delete(f.keysByVersion, versionID)
	return 0, "1", nil
}

func TestBackupServicePutRoomKeysOK(t *testing.T) {
	store := &fakeBackupStorage{
		getResult: &domain.VersaoBackup{IDVersao: 3, IDUsuario: "@alice:example.com"},
	}
	svc := NewBackupService(&roomsvcFakeWorkUnit{}, store)

	keys := []domain.ChaveBackup{
		{IDCanal: "!room:example.org", IDSessao: "session1", SessionData: json.RawMessage(`{}`)},
	}
	count, etag, err := svc.PutRoomKeys(context.Background(), PutRoomKeysParams{
		UserID: "@alice:example.com", Version: "3", Keys: keys,
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
	if etag == "" {
		t.Fatal("expected non-empty etag")
	}
}

func TestBackupServicePutRoomKeysWrongVersion(t *testing.T) {
	store := &fakeBackupStorage{
		getResult: &domain.VersaoBackup{IDVersao: 5, IDUsuario: "@alice:example.com"},
		versionsByID: map[int64]*domain.VersaoBackup{
			3: {IDVersao: 3, IDUsuario: "@alice:example.com"},
		},
	}
	svc := NewBackupService(&roomsvcFakeWorkUnit{}, store)

	_, _, err := svc.PutRoomKeys(context.Background(), PutRoomKeysParams{
		UserID: "@alice:example.com", Version: "3",
	})

	var wrongVersion *ErrWrongVersion
	if !errors.As(err, &wrongVersion) {
		t.Fatalf("expected ErrWrongVersion, got %v", err)
	}
	if wrongVersion.CurrentVersion != "5" {
		t.Fatalf("expected current_version '5', got %s", wrongVersion.CurrentVersion)
	}
}

func TestBackupServicePutRoomKeysNotFound(t *testing.T) {
	store := &fakeBackupStorage{}
	svc := NewBackupService(&roomsvcFakeWorkUnit{}, store)

	_, _, err := svc.PutRoomKeys(context.Background(), PutRoomKeysParams{
		UserID: "@alice:example.com", Version: "1",
	})
	if !errors.Is(err, ErrBackupNotFound) {
		t.Fatalf("expected ErrBackupNotFound, got %v", err)
	}
}

func TestBackupServiceDeleteRoomKeysOK(t *testing.T) {
	store := &fakeBackupStorage{
		versionsByID: map[int64]*domain.VersaoBackup{
			3: {IDVersao: 3, IDUsuario: "@alice:example.com"},
		},
		keysByVersion: map[int64][]domain.ChaveBackup{
			3: {{IDCanal: "!room:example.org", IDSessao: "s1"}},
		},
	}
	svc := NewBackupService(&roomsvcFakeWorkUnit{}, store)

	count, _, err := svc.DeleteRoomKeys(context.Background(), "@alice:example.com", "3")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Fatalf("expected count 0 after delete, got %d", count)
	}
	if len(store.keysByVersion[3]) != 0 {
		t.Fatal("expected keys to be removed")
	}
}

func TestBackupServiceDeleteRoomKeysNotFound(t *testing.T) {
	store := &fakeBackupStorage{}
	svc := NewBackupService(&roomsvcFakeWorkUnit{}, store)

	_, _, err := svc.DeleteRoomKeys(context.Background(), "@alice:example.com", "99")
	if !errors.Is(err, ErrBackupNotFound) {
		t.Fatalf("expected ErrBackupNotFound, got %v", err)
	}
}
