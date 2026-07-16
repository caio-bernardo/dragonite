package presence

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

// Fakes

type routeCanalStore struct {
	joinedRooms map[string][]string
}

func newRouteCanalStore() *routeCanalStore {
	return &routeCanalStore{joinedRooms: make(map[string][]string)}
}

func (f *routeCanalStore) Create(ctx context.Context, roomID, userID string) (*domain.Canal, error) {
	return nil, nil
}
func (f *routeCanalStore) GetCanalParticipatingServers(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}
func (f *routeCanalStore) GetByID(ctx context.Context, canalID string) (*domain.Canal, error) {
	return nil, nil
}
func (f *routeCanalStore) GetJoinRule(ctx context.Context, roomID string) (string, error) {
	return "", nil
}
func (f *routeCanalStore) GetUserJoinedRooms(ctx context.Context, userID string) ([]string, error) {
	return f.joinedRooms[userID], nil
}
func (f *routeCanalStore) GetUserLeftRooms(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}
func (f *routeCanalStore) GetUserMembership(ctx context.Context, roomID, userID string) (string, error) {
	return "", nil
}
func (f *routeCanalStore) GetUserMembershipRecord(ctx context.Context, roomID, userID string) (string, bool, error) {
	return "", false, nil
}
func (f *routeCanalStore) GetStateEventID(ctx context.Context, canalID string, stateType, stateKey string) (string, bool) {
	return "", false
}
func (f *routeCanalStore) UpsertMembership(ctx context.Context, roomID, userID, membership, id_evento string) error {
	return nil
}
func (f *routeCanalStore) UpsertCurrentState(ctx context.Context, canalID, stateType, stateKey, eventID string) error {
	return nil
}
func (f *routeCanalStore) GetAllPublic(ctx context.Context, offset, limit int) ([]domain.Canal, error) {
	return nil, nil
}
func (f *routeCanalStore) UpdateForwardExtremities(ctx context.Context, canalID string, newEventID string, prevEvents []string) error {
	return nil
}
func (f *routeCanalStore) GetForwardExtremities(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}
func (f *routeCanalStore) SaveAlias(ctx context.Context, roomID, fullAlias string) error {
	return nil
}

type routePresenceStore struct {
	data map[string]domain.Presence
}

func newRoutePresenceStore() *routePresenceStore {
	return &routePresenceStore{data: make(map[string]domain.Presence)}
}

func (f *routePresenceStore) UpsertPresence(ctx context.Context, presence domain.Presence) error {
	f.data[presence.IDUsuario] = presence
	return nil
}

func (f *routePresenceStore) GetPresence(ctx context.Context, userID string) (*domain.Presence, error) {
	p, ok := f.data[userID]
	if !ok {
		return nil, nil
	}
	return &p, nil
}

func ctxWithUser(userID string) context.Context {
	return context.WithValue(context.Background(), types.UserIDKey, userID)
}

func assertErrCode(t *testing.T, rec *httptest.ResponseRecorder, expected string) {
	t.Helper()
	var resp struct {
		ErrCode string `json:"errcode"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.ErrCode != expected {
		t.Fatalf("expected errcode %s, got %s", expected, resp.ErrCode)
	}
}

// Testes de GET

func TestGetPresenceStatus_Self(t *testing.T) {
	canalStore := newRouteCanalStore()
	presenceStore := newRoutePresenceStore()
	msg := "Fazendo cupcakes"
	presenceStore.data["@alice:example.com"] = domain.Presence{
		IDUsuario: "@alice:example.com",
		State:     domain.PresenceOnline,
		StatusMsg: &msg,
	}
	svc := usecase.NewPresenceService(presenceStore, canalStore)
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/presence/@alice:example.com/status", nil)
	req.SetPathValue("userId", "@alice:example.com")
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.getPresenceStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}

	var resp PresenceStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Presence != "online" {
		t.Fatalf("expected presence online, got %s", resp.Presence)
	}
	if resp.StatusMsg == nil || *resp.StatusMsg != msg {
		t.Fatalf("expected status_msg %q, got %v", msg, resp.StatusMsg)
	}
	if resp.CurrentlyActive {
		t.Fatalf("expected currently_active false, got true")
	}
}

func TestGetPresenceStatus_SharedRoomAllowed(t *testing.T) {
	canalStore := newRouteCanalStore()
	canalStore.joinedRooms["@alice:example.com"] = []string{"!room1:example.com"}
	canalStore.joinedRooms["@bob:example.com"] = []string{"!room1:example.com"}
	presenceStore := newRoutePresenceStore()
	presenceStore.data["@bob:example.com"] = domain.Presence{IDUsuario: "@bob:example.com", State: domain.PresenceUnavailable}
	svc := usecase.NewPresenceService(presenceStore, canalStore)
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/presence/@bob:example.com/status", nil)
	req.SetPathValue("userId", "@bob:example.com")
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.getPresenceStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
}

func TestGetPresenceStatus_NoSharedRoomForbidden(t *testing.T) {
	canalStore := newRouteCanalStore()
	canalStore.joinedRooms["@alice:example.com"] = []string{"!room1:example.com"}
	canalStore.joinedRooms["@bob:example.com"] = []string{"!room2:example.com"}
	presenceStore := newRoutePresenceStore()
	presenceStore.data["@bob:example.com"] = domain.Presence{IDUsuario: "@bob:example.com", State: domain.PresenceOnline}
	svc := usecase.NewPresenceService(presenceStore, canalStore)
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/presence/@bob:example.com/status", nil)
	req.SetPathValue("userId", "@bob:example.com")
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.getPresenceStatus(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d — body: %s", rec.Code, rec.Body.String())
	}
	assertErrCode(t, rec, "M_FORBIDDEN")
}

func TestGetPresenceStatus_NotFound(t *testing.T) {
	svc := usecase.NewPresenceService(newRoutePresenceStore(), newRouteCanalStore())
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/presence/@alice:example.com/status", nil)
	req.SetPathValue("userId", "@alice:example.com")
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.getPresenceStatus(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_UNKNOWN")
}

// Testes de PUT

func TestPutPresenceStatus_Success(t *testing.T) {
	presenceStore := newRoutePresenceStore()
	svc := usecase.NewPresenceService(presenceStore, newRouteCanalStore())
	h := NewHandler(svc)

	body := bytes.NewBufferString(`{"presence":"online","status_msg":"I am here."}`)
	req := httptest.NewRequest(http.MethodPut, "/_matrix/client/v3/presence/@alice:example.com/status", body)
	req.SetPathValue("userId", "@alice:example.com")
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.putPresenceStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}

	saved, _ := presenceStore.GetPresence(context.Background(), "@alice:example.com")
	if saved == nil || saved.State != domain.PresenceOnline {
		t.Fatalf("expected saved presence online, got %+v", saved)
	}
	if saved.StatusMsg == nil || *saved.StatusMsg != "I am here." {
		t.Fatalf("expected status_msg to be saved, got %v", saved.StatusMsg)
	}
}

func TestPutPresenceStatus_CannotSetOtherUser(t *testing.T) {
	svc := usecase.NewPresenceService(newRoutePresenceStore(), newRouteCanalStore())
	h := NewHandler(svc)

	body := bytes.NewBufferString(`{"presence":"online"}`)
	req := httptest.NewRequest(http.MethodPut, "/_matrix/client/v3/presence/@bob:example.com/status", body)
	req.SetPathValue("userId", "@bob:example.com")
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.putPresenceStatus(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_FORBIDDEN")
}

func TestPutPresenceStatus_InvalidPresenceValue(t *testing.T) {
	svc := usecase.NewPresenceService(newRoutePresenceStore(), newRouteCanalStore())
	h := NewHandler(svc)

	body := bytes.NewBufferString(`{"presence":"dormindo"}`)
	req := httptest.NewRequest(http.MethodPut, "/_matrix/client/v3/presence/@alice:example.com/status", body)
	req.SetPathValue("userId", "@alice:example.com")
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.putPresenceStatus(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_INVALID_PARAM")
}

func TestPutPresenceStatus_MissingPresenceField(t *testing.T) {
	svc := usecase.NewPresenceService(newRoutePresenceStore(), newRouteCanalStore())
	h := NewHandler(svc)

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPut, "/_matrix/client/v3/presence/@alice:example.com/status", body)
	req.SetPathValue("userId", "@alice:example.com")
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.putPresenceStatus(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_MISSING_PARAM")
}