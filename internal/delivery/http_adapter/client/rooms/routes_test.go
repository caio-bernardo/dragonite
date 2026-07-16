package rooms

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

// fakeRoomsCanalStore implementa usecase.CanalStorage com campos configuráveis,
type fakeRoomsCanalStore struct {
	membershipStatus string
	membershipFound  bool
	membershipErr    error

	stateEventID    string
	stateEventFound bool
}

func (f *fakeRoomsCanalStore) Create(ctx context.Context, roomID, userID string) (*domain.Canal, error) {
	return nil, nil
}
func (f *fakeRoomsCanalStore) GetByID(ctx context.Context, canalID string) (*domain.Canal, error) {
	return nil, nil
}
func (f *fakeRoomsCanalStore) GetCanalParticipatingServers(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}
func (f *fakeRoomsCanalStore) GetJoinRule(ctx context.Context, roomID string) (string, error) {
	return "", nil
}
func (f *fakeRoomsCanalStore) GetUserJoinedRooms(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}
func (f *fakeRoomsCanalStore) GetUserLeftRooms(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}
func (f *fakeRoomsCanalStore) GetUserMembership(ctx context.Context, roomID, userID string) (string, error) {
	return f.membershipStatus, f.membershipErr
}
func (f *fakeRoomsCanalStore) GetUserMembershipRecord(ctx context.Context, roomID, userID string) (string, bool, error) {
	return f.membershipStatus, f.membershipFound, f.membershipErr
}
func (f *fakeRoomsCanalStore) GetStateEventID(ctx context.Context, canalID string, stateType, stateKey string) (string, bool) {
	return f.stateEventID, f.stateEventFound
}
func (f *fakeRoomsCanalStore) UpsertMembership(ctx context.Context, roomID, userID, membership, id_evento string) error {
	return nil
}
func (f *fakeRoomsCanalStore) UpsertCurrentState(ctx context.Context, canalID, stateType, stateKey, eventID string) error {
	return nil
}
func (f *fakeRoomsCanalStore) GetAllPublic(ctx context.Context, offset, limit int) ([]domain.Canal, error) {
	return nil, nil
}
func (f *fakeRoomsCanalStore) UpdateForwardExtremities(ctx context.Context, canalID string, newEventID string, prevEvents []string) error {
	return nil
}
func (f *fakeRoomsCanalStore) GetForwardExtremities(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}
func (f *fakeRoomsCanalStore) SaveAlias(ctx context.Context, roomID, fullAlias string) error {
	return nil
}

// fakeRoomsEventoStore implementa usecase.EventoStorage com campos configuráveis
type fakeRoomsEventoStore struct {
	evento    *domain.Evento
	eventoErr error
}

func (f *fakeRoomsEventoStore) GetSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}
func (f *fakeRoomsEventoStore) GetMaxDepthFromEventos(ctx context.Context, eventIDs []string) (int64, error) {
	return 0, nil
}
func (f *fakeRoomsEventoStore) GetMaxStreamOrdering(ctx context.Context) (int64, error) {
	return 0, nil
}
func (f *fakeRoomsEventoStore) SaveEvento(ctx context.Context, event *domain.Evento) error {
	return nil
}
func (f *fakeRoomsEventoStore) GetEvento(ctx context.Context, eventID string) (*domain.Evento, error) {
	return f.evento, f.eventoErr
}
func (f *fakeRoomsEventoStore) GetEventsSince(ctx context.Context, roomID string, limit int, eventIDs []string) ([]domain.Evento, error) {
	return nil, nil
}
func (f *fakeRoomsEventoStore) GetEventsOfCanalSince(ctx context.Context, userID string, roomID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}
func (f *fakeRoomsEventoStore) CheckEventoExists(ctx context.Context, eventID string) (bool, error) {
	return false, nil
}
func (f *fakeRoomsEventoStore) GetCurrentStateEvents(ctx context.Context, roomID string) ([]domain.Evento, error) {
	return nil, nil
}
func (f *fakeRoomsEventoStore) GetStateAndAuthChainIDs(ctx context.Context, roomID string, eventID string) ([]string, []string, error) {
	return nil, nil, nil
}
func (f *fakeRoomsEventoStore) GetMissingEvents(ctx context.Context, roomID string, earliestEvents, latestEvents []string, limit int, minDepth int64) ([]domain.Evento, error) {
	return nil, nil
}
func (f *fakeRoomsEventoStore) SaveReceipt(ctx context.Context, userID, roomID, receiptType, eventID string, ts int64) error {
	return nil
}
func (f *fakeRoomsEventoStore) GetRoomMessagesHistory(ctx context.Context, roomID string, fromToken int64, dir string, limit int) ([]domain.Evento, error) {
	return nil, nil
}
func (f *fakeRoomsEventoStore) GetEventsOfCanalSinceLeft(ctx context.Context, userID string, roomID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}
func (f *fakeRoomsEventoStore) GetStateAndAuthChainEvents(ctx context.Context, roomID string, userID string) ([]domain.Evento, []domain.Evento, error) {
	return nil, nil, nil
}
func (f *fakeRoomsEventoStore) GetRoomMemberEvents(ctx context.Context, roomID string) ([]domain.Evento, error) {
	return nil, nil
}

// newTestGetRoomStateHandler monta um Handler mínimo, só com roomInteractions preenchido, suficiente para testar getRoomState
func newTestGetRoomStateHandler(canalStore *fakeRoomsCanalStore, eventoStore *fakeRoomsEventoStore) *Handler {
	svc := usecase.NewRoomInteractionService(canalStore, eventoStore, nil, nil, nil, "example.com", "", nil)
	return &Handler{roomInteractions: svc}
}

func newGetRoomStateRequest(roomID, eventType, stateKey, format string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/rooms/"+roomID+"/state/"+eventType+"/"+stateKey, nil)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))
	req.SetPathValue("roomId", roomID)
	req.SetPathValue("eventType", eventType)
	req.SetPathValue("stateKey", stateKey)
	if format != "" {
		q := req.URL.Query()
		q.Set("format", format)
		req.URL.RawQuery = q.Encode()
	}
	return req
}

func TestGetRoomStateContentOK(t *testing.T) {
	evento := &domain.Evento{
		ID:               "$event1",
		CanalID:          "!room1:example.com",
		Sender:           "@bob:example.com",
		Tipo:             "m.room.name",
		Content:          json.RawMessage(`{"name":"Test Room"}`),
		OrigemServidorTS: 12345,
	}
	canalStore := &fakeRoomsCanalStore{membershipStatus: "join", membershipFound: true, stateEventID: "$event1", stateEventFound: true}
	eventoStore := &fakeRoomsEventoStore{evento: evento}
	h := newTestGetRoomStateHandler(canalStore, eventoStore)

	req := newGetRoomStateRequest("!room1:example.com", "m.room.name", "", "")
	rec := httptest.NewRecorder()

	h.getRoomState(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["name"] != "Test Room" {
		t.Fatalf("expected content to be the raw state content, got %v", body)
	}
}

func TestGetRoomStateFormatEventOK(t *testing.T) {
	stateKey := ""
	evento := &domain.Evento{
		ID:               "$event1",
		CanalID:          "!room1:example.com",
		Sender:           "@bob:example.com",
		Tipo:             "m.room.name",
		StateKey:         &stateKey,
		Content:          json.RawMessage(`{"name":"Test Room"}`),
		OrigemServidorTS: 12345,
	}
	canalStore := &fakeRoomsCanalStore{membershipStatus: "join", membershipFound: true, stateEventID: "$event1", stateEventFound: true}
	eventoStore := &fakeRoomsEventoStore{evento: evento}
	h := newTestGetRoomStateHandler(canalStore, eventoStore)

	req := newGetRoomStateRequest("!room1:example.com", "m.room.name", "", "event")
	rec := httptest.NewRecorder()

	h.getRoomState(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp StateEventFull
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.EventID != "$event1" || resp.Type != "m.room.name" || resp.RoomID != "!room1:example.com" || resp.Sender != "@bob:example.com" {
		t.Fatalf("unexpected full event body: %+v", resp)
	}
}

func TestGetRoomStateForbiddenNeverMember(t *testing.T) {
	canalStore := &fakeRoomsCanalStore{membershipFound: false} // nunca teve registro de membership
	eventoStore := &fakeRoomsEventoStore{}
	h := newTestGetRoomStateHandler(canalStore, eventoStore)

	req := newGetRoomStateRequest("!room1:example.com", "m.room.name", "", "")
	rec := httptest.NewRecorder()

	h.getRoomState(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	var errResp struct {
		ErrCode string `json:"errcode"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if errResp.ErrCode != "M_FORBIDDEN" {
		t.Fatalf("expected M_FORBIDDEN, got %s", errResp.ErrCode)
	}
}

func TestGetRoomStateNotFound(t *testing.T) {
	canalStore := &fakeRoomsCanalStore{membershipStatus: "join", membershipFound: true, stateEventFound: false}
	eventoStore := &fakeRoomsEventoStore{}
	h := newTestGetRoomStateHandler(canalStore, eventoStore)

	req := newGetRoomStateRequest("!room1:example.com", "m.room.custom", "", "")
	rec := httptest.NewRecorder()

	h.getRoomState(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}

	var errResp struct {
		ErrCode string `json:"errcode"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if errResp.ErrCode != "M_NOT_FOUND" {
		t.Fatalf("expected M_NOT_FOUND, got %s", errResp.ErrCode)
	}
}

func TestGetRoomStateInvalidFormat(t *testing.T) {
	canalStore := &fakeRoomsCanalStore{membershipStatus: "join", membershipFound: true}
	eventoStore := &fakeRoomsEventoStore{}
	h := newTestGetRoomStateHandler(canalStore, eventoStore)

	req := newGetRoomStateRequest("!room1:example.com", "m.room.name", "", "bogus")
	rec := httptest.NewRecorder()

	h.getRoomState(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestGetRoomStateMissingToken(t *testing.T) {
	canalStore := &fakeRoomsCanalStore{}
	eventoStore := &fakeRoomsEventoStore{}
	h := newTestGetRoomStateHandler(canalStore, eventoStore)

	// requisição sem user_id no contexto, simula ausência do middleware de auth
	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/rooms/!room1:example.com/state/m.room.name/", nil)
	req.SetPathValue("roomId", "!room1:example.com")
	req.SetPathValue("eventType", "m.room.name")
	req.SetPathValue("stateKey", "")
	rec := httptest.NewRecorder()

	h.getRoomState(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}
