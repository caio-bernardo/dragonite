package roomkeys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
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

// roomkeysFakeWorkUnit é um WorkUnit fake local a este pacote
type roomkeysFakeWorkUnit struct{}

func (f *roomkeysFakeWorkUnit) Execute(ctx context.Context, fn func(txCtx context.Context) error) error {
	return fn(ctx)
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

func TestGetLatestVersionOK(t *testing.T) {
	existing := &domain.VersaoBackup{
		IDVersao:  1,
		IDUsuario: "@alice:example.com",
		Algorithm: "m.megolm_backup.v1.curve25519-aes-sha2",
		AuthData:  json.RawMessage(`{"public_key":"abcdefg"}`),
		Count:     42,
		ETag:      "anopaquestring",
	}
	store := &fakeBackupStorage{getResult: existing}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/room_keys/version", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.getLatestVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp BackupVersionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Version != "1" {
		t.Fatalf("expected version '1', got %s", resp.Version)
	}
	if resp.Count != 42 {
		t.Fatalf("expected count 42, got %d", resp.Count)
	}
	if resp.ETag != "anopaquestring" {
		t.Fatalf("expected etag 'anopaquestring', got %s", resp.ETag)
	}
}

func TestGetLatestVersionNotFound(t *testing.T) {
	store := &fakeBackupStorage{getResult: nil}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/room_keys/version", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.getLatestVersion(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}

	var resp struct {
		ErrCode string `json:"errcode"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.ErrCode != "M_NOT_FOUND" {
		t.Fatalf("expected M_NOT_FOUND, got %s", resp.ErrCode)
	}
}

func TestGetLatestVersionMissingAuth(t *testing.T) {
	store := &fakeBackupStorage{}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/room_keys/version", nil)
	rec := httptest.NewRecorder()

	h.getLatestVersion(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestCreateVersionOK(t *testing.T) {
	store := &fakeBackupStorage{nextID: 7}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	body := bytes.NewBufferString(`{"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abcdefg"}}`)
	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/room_keys/version", body)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.createVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp CreateBackupVersionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Version != "7" {
		t.Fatalf("expected version '7', got %s", resp.Version)
	}
	if store.created == nil {
		t.Fatal("expected backup to be persisted")
	}
	if store.created.IDUsuario != "@alice:example.com" {
		t.Fatalf("expected id_usuario '@alice:example.com', got %s", store.created.IDUsuario)
	}
}

func TestCreateVersionMissingParams(t *testing.T) {
	store := &fakeBackupStorage{}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	body := bytes.NewBufferString(`{"algorithm":""}`)
	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/room_keys/version", body)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.createVersion(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	var resp struct {
		ErrCode string `json:"errcode"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.ErrCode != "M_MISSING_PARAM" {
		t.Fatalf("expected M_MISSING_PARAM, got %s", resp.ErrCode)
	}
}

func TestCreateVersionInvalidJSON(t *testing.T) {
	store := &fakeBackupStorage{}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	body := bytes.NewBufferString(`{invalid`)
	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/room_keys/version", body)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.createVersion(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestCreateVersionStorageError(t *testing.T) {
	store := &fakeBackupStorage{createErr: errors.New("db connection lost")}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	body := bytes.NewBufferString(`{"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{"public_key":"abcdefg"}}`)
	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/room_keys/version", body)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.createVersion(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
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

func TestGetRoomKeysOK(t *testing.T) {
	store := &fakeBackupStorage{
		versionsByID: map[int64]*domain.VersaoBackup{
			3: {IDVersao: 3, IDUsuario: "@alice:example.com"},
		},
		keysByVersion: map[int64][]domain.ChaveBackup{
			3: {{IDCanal: "!room:example.org", IDSessao: "session1", SessionData: json.RawMessage(`{"ciphertext":"abc"}`)}},
		},
	}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/room_keys/keys?version=3", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.getRoomKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp GetRoomKeysResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	room, ok := resp.Rooms["!room:example.org"]
	if !ok {
		t.Fatal("expected room in response")
	}
	if _, ok := room.Sessions["session1"]; !ok {
		t.Fatal("expected session1 in response")
	}
}

func TestGetRoomKeysNotFound(t *testing.T) {
	store := &fakeBackupStorage{}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/room_keys/keys?version=99", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.getRoomKeys(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}
}

func TestGetRoomKeysMissingVersion(t *testing.T) {
	store := &fakeBackupStorage{}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/room_keys/keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.getRoomKeys(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestPutRoomKeysOK(t *testing.T) {
	store := &fakeBackupStorage{
		getResult: &domain.VersaoBackup{IDVersao: 3, IDUsuario: "@alice:example.com"},
	}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	body := bytes.NewBufferString(`{
		"rooms": {
			"!room:example.org": {
				"sessions": {
					"session1": {
						"first_message_index": 1,
						"forwarded_count": 0,
						"is_verified": true,
						"session_data": {"ciphertext":"abc"}
					}
				}
			}
		}
	}`)
	req := httptest.NewRequest(http.MethodPut, "/_matrix/client/v3/room_keys/keys?version=3", body)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.putRoomKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, body=%s", rec.Code, rec.Body.String())
	}

	var resp RoomKeysUpdateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Count != 1 {
		t.Fatalf("expected count 1, got %d", resp.Count)
	}
}

func TestPutRoomKeysWrongVersion(t *testing.T) {
	store := &fakeBackupStorage{
		getResult: &domain.VersaoBackup{IDVersao: 5, IDUsuario: "@alice:example.com"},
		versionsByID: map[int64]*domain.VersaoBackup{
			3: {IDVersao: 3, IDUsuario: "@alice:example.com"},
		},
	}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	body := bytes.NewBufferString(`{"rooms":{}}`)
	req := httptest.NewRequest(http.MethodPut, "/_matrix/client/v3/room_keys/keys?version=3", body)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.putRoomKeys(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}

	var resp WrongVersionErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CurrentVersion != "5" {
		t.Fatalf("expected current_version '5', got %s", resp.CurrentVersion)
	}
}

func TestDeleteRoomKeysOK(t *testing.T) {
	store := &fakeBackupStorage{
		versionsByID: map[int64]*domain.VersaoBackup{
			3: {IDVersao: 3, IDUsuario: "@alice:example.com"},
		},
	}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	req := httptest.NewRequest(http.MethodDelete, "/_matrix/client/v3/room_keys/keys?version=3", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.deleteRoomKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestDeleteRoomKeysNotFound(t *testing.T) {
	store := &fakeBackupStorage{}
	svc := usecase.NewBackupService(&roomkeysFakeWorkUnit{}, store)
	h := NewHandler(svc, nil)

	req := httptest.NewRequest(http.MethodDelete, "/_matrix/client/v3/room_keys/keys?version=99", nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	rec := httptest.NewRecorder()

	h.deleteRoomKeys(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}
}
