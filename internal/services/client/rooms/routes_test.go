package rooms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
	"github.com/caio-bernardo/dragonite/internal/repository"
)

// MockChannelStore is a mock implementation of repository.ChannelStore for testing
type MockChannelStore struct {
	createCalled         bool
	createdCanal         *model.Canal
	getByIDResult        *model.Canal
	getByIDErr           error
	listPublicResult     []model.Canal
	listPublicNextBatch  string
	listPublicTotal      int
	updateMemberCountErr error
	upsertEstadoAtualErr error
}

func (m *MockChannelStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Canal, error) {
	return []model.Canal{}, nil
}

func (m *MockChannelStore) GetByID(ctx context.Context, id string) (*model.Canal, error) {
	return m.getByIDResult, m.getByIDErr
}

func (m *MockChannelStore) Create(ctx context.Context, props *model.Canal) error {
	m.createCalled = true
	m.createdCanal = props
	return nil
}

func (m *MockChannelStore) Update(ctx context.Context, props *model.Canal) error {
	return nil
}

func (m *MockChannelStore) Delete(ctx context.Context, id_canal string) (*model.Canal, error) {
	return nil, nil
}

func (m *MockChannelStore) ListPublic(_ context.Context, _ repository.ListPublicParams) ([]model.Canal, string, string, int, error) {
    return m.listPublicResult, m.listPublicNextBatch, "", m.listPublicTotal, nil
}

func (m *MockChannelStore) UpdateMemberCount(ctx context.Context, canalID string, delta int) error {
	return m.updateMemberCountErr
}

func (m *MockChannelStore) UpsertEstadoAtual(ctx context.Context, estado *model.EstadoAtualCanal) error {
	return m.upsertEstadoAtualErr
}

// MockUsuarioCanalStore is a mock implementation of repository.UsuarioCanalStore for testing
type MockUsuarioCanalStore struct {
	addOrUpdateMembershipCalled bool
	addOrUpdateMembershipErr    error
	getByComposedIDResult       *model.UsuarioCanal
	getByComposedIDErr          error
	getJoinedUserIDsInRoomErr   error
	joinedUserIDs               []string
}

func (m *MockUsuarioCanalStore) GetAll(ctx context.Context, filter util.Filter) ([]model.UsuarioCanal, error) {
	return []model.UsuarioCanal{}, nil
}

func (m *MockUsuarioCanalStore) GetByComposedID(ctx context.Context, id_usuario string, id_canal string) (*model.UsuarioCanal, error) {
	return m.getByComposedIDResult, m.getByComposedIDErr
}

func (m *MockUsuarioCanalStore) GetAllByUsuarioID(ctx context.Context, id_usuario string) ([]model.UsuarioCanal, error) {
	return []model.UsuarioCanal{}, nil
}

func (m *MockUsuarioCanalStore) GetAllByCanalID(ctx context.Context, id_canal string) ([]model.UsuarioCanal, error) {
	return []model.UsuarioCanal{}, nil
}

func (m *MockUsuarioCanalStore) Create(ctx context.Context, props *model.UsuarioCanal) error {
	return nil
}

func (m *MockUsuarioCanalStore) Update(ctx context.Context, props *model.UsuarioCanal) error {
	return nil
}

func (m *MockUsuarioCanalStore) Delete(ctx context.Context, id_usuario string, id_canal string) (*model.UsuarioCanal, error) {
	return nil, nil
}

func (m *MockUsuarioCanalStore) AddOrUpdateMembership(ctx context.Context, mem *model.UsuarioCanal) error {
	m.addOrUpdateMembershipCalled = true
	return m.addOrUpdateMembershipErr
}

func (m *MockUsuarioCanalStore) GetJoinedUserIDsInRoom(ctx context.Context, roomID string) ([]string, error) {
	return m.joinedUserIDs, m.getJoinedUserIDsInRoomErr
}

// MockEventoStore is a mock implementation of repository.EventoStore for testing
type MockEventoStore struct {
	createCalled    bool
	createdEvento   *model.Evento
	getByTxnIDErr   error
	getByTxnIDEvent *model.Evento
	getCurrentStateEventsResult []model.Evento
}

func (m *MockEventoStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Evento, error) {
	return []model.Evento{}, nil
}

func (m *MockEventoStore) GetByID(ctx context.Context, id string) (*model.Evento, error) {
	return nil, nil
}

func (m *MockEventoStore) GetByTxnID(ctx context.Context, senderID, txnID string) (*model.Evento, error) {
	return m.getByTxnIDEvent, m.getByTxnIDErr
}

func (m *MockEventoStore) Create(ctx context.Context, props *model.Evento) error {
	m.createCalled = true
	m.createdEvento = props
	return nil
}

func (m *MockEventoStore) Update(ctx context.Context, props *model.Evento) error {
	return nil
}

func (m *MockEventoStore) Delete(ctx context.Context, id string) (*model.Evento, error) {
	return nil, nil
}

func (m *MockEventoStore) CheckNew(ctx context.Context, userID string, since model.SyncToken) (bool, error) {
	return false, nil
}

func (m *MockEventoStore) GetSince(ctx context.Context, userID string, since model.SyncToken) ([]model.Evento, model.SyncToken, error) {
	return []model.Evento{}, model.SyncToken{}, nil
}

func (m *MockEventoStore) GetMaxGlobalStreamOrdering(ctx context.Context) (int64, error) {
	return 0, nil
}

func (m *MockEventoStore) GetCurrentStateEvents(ctx context.Context, roomID string) ([]model.Evento, error) {
	return m.getCurrentStateEventsResult, nil
}
// MockNotifier is a mock implementation of notifier.Notifier for testing
type MockNotifier struct {
	notifiedUsers map[string]int
}

func NewMockNotifier() *MockNotifier {
	return &MockNotifier{notifiedUsers: make(map[string]int)}
}

func (m *MockNotifier) Subscribe(userID string) chan struct{} {
	return make(chan struct{}, 1)
}

func (m *MockNotifier) Unsubscribe(userID string, ch chan struct{}) {
	// noop
}

func (m *MockNotifier) Notify(userID string) {
	m.notifiedUsers[userID]++
}

// TestGetPublicRooms tests the getPublicRooms handler
func TestGetPublicRooms(t *testing.T) {
	t.Run("returns_public_rooms", func(t *testing.T) {
		canalStore := &MockChannelStore{
			listPublicResult: []model.Canal{
				{
					ID:          "!room1:example.com",
					Nome:        "Room 1",
					Descricao:   "Test Room",
					Foto:        "https://example.com/room.png",
					IsPublic:    true,
					MemberCount: 5,
					JoinRules:   "public",
					GuestAccess: "forbidden",
					CanonAlias:  nil,
				},
			},
		}

		handler := NewHandler(canalStore, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		req := httptest.NewRequest("GET", "/_matrix/client/v3/publicRooms", nil)
		w := httptest.NewRecorder()

		handler.getPublicRooms(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		var resp PublicRoomsResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Errorf("failed to decode response: %v", err)
		}

		if len(resp.Chunk) != 1 {
			t.Errorf("expected 1 room, got %d", len(resp.Chunk))
		}

		if resp.Chunk[0].RoomID != "!room1:example.com" {
			t.Errorf("expected room id !room1:example.com, got %s", resp.Chunk[0].RoomID)
		}
	})

	t.Run("respects_limit_parameter", func(t *testing.T) {
		canalStore := &MockChannelStore{
			listPublicResult: []model.Canal{},
		}

		handler := NewHandler(canalStore, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		req := httptest.NewRequest("GET", "/_matrix/client/v3/publicRooms?limit=10", nil)
		w := httptest.NewRecorder()

		handler.getPublicRooms(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})

	t.Run("invalid_limit_returns_400", func(t *testing.T) {
		handler := NewHandler(&MockChannelStore{}, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		req := httptest.NewRequest("GET", "/_matrix/client/v3/publicRooms?limit=invalid", nil)
		w := httptest.NewRecorder()

		handler.getPublicRooms(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})
}

// TestPostCreateRoom tests the postCreateRoom handler
func TestPostCreateRoom(t *testing.T) {
	t.Run("success_public_room", func(t *testing.T) {
		canalStore := &MockChannelStore{}
		usuarioCanalStore := &MockUsuarioCanalStore{}
		notifier := NewMockNotifier()
		handler := NewHandler(canalStore, usuarioCanalStore, &MockEventoStore{}, "example.com", notifier)

		req := CreateRoomRequest{
			Visibility: "public",
			Name:       stringPtr("My Room"),
			Topic:      stringPtr("Test topic"),
		}

		body, _ := json.Marshal(req)
		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/createRoom", bytes.NewReader(body))
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))

		w := httptest.NewRecorder()
		handler.postCreateRoom(w, httpReq)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		if !canalStore.createCalled {
			t.Errorf("expected canal store Create to be called")
		}

		if !usuarioCanalStore.addOrUpdateMembershipCalled {
			t.Errorf("expected usuario canal store AddOrUpdateMembership to be called")
		}

		var resp CreateRoomResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Errorf("failed to decode response: %v", err)
		}

		if resp.RoomID == "" {
			t.Errorf("expected room_id to be set")
		}
	})

	t.Run("success_with_preset", func(t *testing.T) {
		canalStore := &MockChannelStore{}
		usuarioCanalStore := &MockUsuarioCanalStore{}
		handler := NewHandler(canalStore, usuarioCanalStore, &MockEventoStore{}, "example.com", NewMockNotifier())

		req := CreateRoomRequest{
			Preset: stringPtr("public_chat"),
		}

		body, _ := json.Marshal(req)
		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/createRoom", bytes.NewReader(body))
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@bob:example.com"))

		w := httptest.NewRecorder()
		handler.postCreateRoom(w, httpReq)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})

	t.Run("missing_auth_token_returns_401", func(t *testing.T) {
		handler := NewHandler(&MockChannelStore{}, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/createRoom", nil)
		w := httptest.NewRecorder()
		handler.postCreateRoom(w, httpReq)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("invalid_json_returns_400", func(t *testing.T) {
		handler := NewHandler(&MockChannelStore{}, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/createRoom", bytes.NewReader([]byte("invalid json")))
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))
		w := httptest.NewRecorder()
		handler.postCreateRoom(w, httpReq)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})
}

// TestPostJoinRoom tests the postJoinRoom handler
func TestPostJoinRoom(t *testing.T) {
	t.Run("success_join_public_room", func(t *testing.T) {
		canalStore := &MockChannelStore{
			getByIDResult: &model.Canal{
				ID:        "!room1:example.com",
				JoinRules: "public",
			},
		}
		usuarioCanalStore := &MockUsuarioCanalStore{}
		notifier := NewMockNotifier()
		handler := NewHandler(canalStore, usuarioCanalStore, &MockEventoStore{}, "example.com", notifier)

		req := JoinRoomRequest{}
		body, _ := json.Marshal(req)
		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/rooms/!room1:example.com/join", bytes.NewReader(body))
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))
		httpReq.SetPathValue("roomId", "!room1:example.com")

		w := httptest.NewRecorder()
		handler.postJoinRoom(w, httpReq)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		if !usuarioCanalStore.addOrUpdateMembershipCalled {
			t.Errorf("expected AddOrUpdateMembership to be called")
		}
	})

	t.Run("join_invite_room_without_invitation_returns_403", func(t *testing.T) {
		canalStore := &MockChannelStore{
			getByIDResult: &model.Canal{
				ID:        "!room1:example.com",
				JoinRules: "invite",
			},
		}
		usuarioCanalStore := &MockUsuarioCanalStore{
			getByComposedIDErr: fmt.Errorf("not found"),
		}
		handler := NewHandler(canalStore, usuarioCanalStore, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/rooms/!room1:example.com/join", nil)
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))
		httpReq.SetPathValue("roomId", "!room1:example.com")

		w := httptest.NewRecorder()
		handler.postJoinRoom(w, httpReq)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected status 403, got %d", w.Code)
		}
	})

	t.Run("missing_room_id_returns_400", func(t *testing.T) {
		handler := NewHandler(&MockChannelStore{}, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/rooms//join", nil)
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))

		w := httptest.NewRecorder()
		handler.postJoinRoom(w, httpReq)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", w.Code)
		}
	})

	t.Run("missing_auth_token_returns_401", func(t *testing.T) {
		handler := NewHandler(&MockChannelStore{}, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/rooms/!room1:example.com/join", nil)
		httpReq.SetPathValue("roomId", "!room1:example.com")

		w := httptest.NewRecorder()
		handler.postJoinRoom(w, httpReq)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})
}

// TestPostLeaveRoom tests the postLeaveRoom handler
func TestPostLeaveRoom(t *testing.T) {
	t.Run("success_leave_room", func(t *testing.T) {
		usuarioCanalStore := &MockUsuarioCanalStore{
			getByComposedIDResult: &model.UsuarioCanal{
				CanalID:   "!room1:example.com",
				UsuarioID: "@alice:example.com",
				Membresia: "join",
				JoinedAt:  time.Now(),
			},
		}
		canalStore := &MockChannelStore{}
		notifier := NewMockNotifier()
		handler := NewHandler(canalStore, usuarioCanalStore, &MockEventoStore{}, "example.com", notifier)

		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/rooms/!room1:example.com/leave", nil)
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))
		httpReq.SetPathValue("roomId", "!room1:example.com")

		w := httptest.NewRecorder()
		handler.postLeaveRoom(w, httpReq)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		if !usuarioCanalStore.addOrUpdateMembershipCalled {
			t.Errorf("expected AddOrUpdateMembership to be called")
		}
	})

	t.Run("not_member_of_room_returns_403", func(t *testing.T) {
		usuarioCanalStore := &MockUsuarioCanalStore{
			getByComposedIDErr: fmt.Errorf("not found"),
		}
		handler := NewHandler(&MockChannelStore{}, usuarioCanalStore, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/rooms/!room1:example.com/leave", nil)
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))
		httpReq.SetPathValue("roomId", "!room1:example.com")

		w := httptest.NewRecorder()
		handler.postLeaveRoom(w, httpReq)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected status 403, got %d", w.Code)
		}
	})

	t.Run("missing_auth_token_returns_401", func(t *testing.T) {
		handler := NewHandler(&MockChannelStore{}, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("POST", "/_matrix/client/v3/rooms/!room1:example.com/leave", nil)
		httpReq.SetPathValue("roomId", "!room1:example.com")

		w := httptest.NewRecorder()
		handler.postLeaveRoom(w, httpReq)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})
}

// TestPutSendEvent tests the putSendEvent handler
func TestPutSendEvent(t *testing.T) {
	t.Run("success_send_event", func(t *testing.T) {
		canalStore := &MockChannelStore{
			getByIDResult: &model.Canal{ID: "!room1:example.com"},
		}
		eventoStore := &MockEventoStore{
			getByTxnIDErr: fmt.Errorf("not found"),
		}
		notifier := NewMockNotifier()
		handler := NewHandler(canalStore, &MockUsuarioCanalStore{}, eventoStore, "example.com", notifier)

		reqBody := map[string]string{"body": "Hello, world!"}
		body, _ := json.Marshal(reqBody)
		httpReq := httptest.NewRequest("PUT", "/_matrix/client/v3/rooms/!room1:example.com/send/m.room.message/txn1", bytes.NewReader(body))
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))
		httpReq.SetPathValue("roomId", "!room1:example.com")
		httpReq.SetPathValue("eventType", "m.room.message")
		httpReq.SetPathValue("txnId", "txn1")

		w := httptest.NewRecorder()
		handler.putSendEvent(w, httpReq)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		if !eventoStore.createCalled {
			t.Errorf("expected evento store Create to be called")
		}

		var resp SendEventResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Errorf("failed to decode response: %v", err)
		}

		if resp.EventID == "" {
			t.Errorf("expected event_id to be set")
		}
	})

	t.Run("idempotent_on_duplicate_txn_id", func(t *testing.T) {
		canalStore := &MockChannelStore{
			getByIDResult: &model.Canal{ID: "!room1:example.com"},
		}
		eventoStore := &MockEventoStore{
			getByTxnIDEvent: &model.Evento{ID: "$event123"},
		}
		handler := NewHandler(canalStore, &MockUsuarioCanalStore{}, eventoStore, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("PUT", "/_matrix/client/v3/rooms/!room1:example.com/send/m.room.message/txn1", nil)
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))
		httpReq.SetPathValue("roomId", "!room1:example.com")
		httpReq.SetPathValue("eventType", "m.room.message")
		httpReq.SetPathValue("txnId", "txn1")

		w := httptest.NewRecorder()
		handler.putSendEvent(w, httpReq)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		var resp SendEventResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Errorf("failed to decode response: %v", err)
		}

		if resp.EventID != "$event123" {
			t.Errorf("expected event_id $event123, got %s", resp.EventID)
		}
	})

	t.Run("room_not_found_returns_403", func(t *testing.T) {
		canalStore := &MockChannelStore{
			getByIDErr: fmt.Errorf("not found"),
		}
		handler := NewHandler(canalStore, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("PUT", "/_matrix/client/v3/rooms/!room1:example.com/send/m.room.message/txn1", nil)
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))
		httpReq.SetPathValue("roomId", "!room1:example.com")
		httpReq.SetPathValue("eventType", "m.room.message")
		httpReq.SetPathValue("txnId", "txn1")

		w := httptest.NewRecorder()
		handler.putSendEvent(w, httpReq)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected status 403, got %d", w.Code)
		}
	})

	t.Run("missing_auth_token_returns_401", func(t *testing.T) {
		handler := NewHandler(&MockChannelStore{}, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("PUT", "/_matrix/client/v3/rooms/!room1:example.com/send/m.room.message/txn1", nil)
		httpReq.SetPathValue("roomId", "!room1:example.com")
		httpReq.SetPathValue("eventType", "m.room.message")
		httpReq.SetPathValue("txnId", "txn1")

		w := httptest.NewRecorder()
		handler.putSendEvent(w, httpReq)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})
}

// TestPutStateEvent tests the putStateEvent handler
func TestPutStateEvent(t *testing.T) {
	t.Run("success_send_state_event", func(t *testing.T) {
		usuarioCanalStore := &MockUsuarioCanalStore{
			getByComposedIDResult: &model.UsuarioCanal{
				CanalID:   "!room1:example.com",
				UsuarioID: "@alice:example.com",
				Membresia: "join",
			},
		}
		canalStore := &MockChannelStore{}
		eventoStore := &MockEventoStore{}
		notifier := NewMockNotifier()
		handler := NewHandler(canalStore, usuarioCanalStore, eventoStore, "example.com", notifier)

		reqBody := map[string]string{"name": "New Room Name"}
		body, _ := json.Marshal(reqBody)
		httpReq := httptest.NewRequest("PUT", "/_matrix/client/v3/rooms/!room1:example.com/state/m.room.name/", bytes.NewReader(body))
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))
		httpReq.SetPathValue("roomId", "!room1:example.com")
		httpReq.SetPathValue("eventType", "m.room.name")
		httpReq.SetPathValue("stateKey", "")

		w := httptest.NewRecorder()
		handler.putStateEvent(w, httpReq)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		if !eventoStore.createCalled {
			t.Errorf("expected evento store Create to be called")
		}

		var resp StateEventResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Errorf("failed to decode response: %v", err)
		}

		if resp.EventID == "" {
			t.Errorf("expected event_id to be set")
		}
	})

	t.Run("not_member_of_room_returns_403", func(t *testing.T) {
		usuarioCanalStore := &MockUsuarioCanalStore{
			getByComposedIDErr: fmt.Errorf("not found"),
		}
		handler := NewHandler(&MockChannelStore{}, usuarioCanalStore, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("PUT", "/_matrix/client/v3/rooms/!room1:example.com/state/m.room.name/", nil)
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), types.UserIDKey, "@alice:example.com"))
		httpReq.SetPathValue("roomId", "!room1:example.com")
		httpReq.SetPathValue("eventType", "m.room.name")
		httpReq.SetPathValue("stateKey", "")

		w := httptest.NewRecorder()
		handler.putStateEvent(w, httpReq)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected status 403, got %d", w.Code)
		}
	})

	t.Run("missing_auth_token_returns_401", func(t *testing.T) {
		handler := NewHandler(&MockChannelStore{}, &MockUsuarioCanalStore{}, &MockEventoStore{}, "example.com", NewMockNotifier())

		httpReq := httptest.NewRequest("PUT", "/_matrix/client/v3/rooms/!room1:example.com/state/m.room.name/", nil)
		httpReq.SetPathValue("roomId", "!room1:example.com")
		httpReq.SetPathValue("eventType", "m.room.name")
		httpReq.SetPathValue("stateKey", "")

		w := httptest.NewRecorder()
		handler.putStateEvent(w, httpReq)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})
}

// Helper function
func stringPtr(s string) *string {
	return &s
}
