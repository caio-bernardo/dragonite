package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
	"github.com/caio-bernardo/dragonite/internal/repository"
)

// MockUserStore is a mock implementation of repository.UserStore for testing
type MockUserStore struct {
	SearchResults []model.Usuario
}

func (m *MockUserStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Usuario, error) {
	return []model.Usuario{}, nil
}

func (m *MockUserStore) GetByID(ctx context.Context, id string) (*model.Usuario, error) {
	return nil, nil
}

func (m *MockUserStore) GetByLocal(ctx context.Context, localpart string) (*model.Usuario, error) {
	return nil, nil
}

func (m *MockUserStore) Create(ctx context.Context, usuario *model.Usuario) error {
	return nil
}

func (m *MockUserStore) Update(ctx context.Context, usuario *model.Usuario) error {
	return nil
}

func (m *MockUserStore) Delete(ctx context.Context, id string) (*model.Usuario, error) {
	return nil, nil
}

func (m *MockUserStore) Search(ctx context.Context, term string, limit int) ([]model.Usuario, error) {
	return m.SearchResults, nil
}

func (m *MockUserStore) GetNameAndPhotoByID(ctx context.Context, id string) (*model.Usuario, error) {
	return nil, nil
}

func (m *MockUserStore) ClearProfileKey(ctx context.Context, userID string, colunaDB string) error {
	return nil
}

func (m *MockUserStore) UpdateProfileKey(ctx context.Context, userID string, colunaDB string, novoValor string) error {
	return nil
}

// MockDeviceStore is a mock implementation of repository.DeviceStore for testing
type MockDeviceStore struct{}

// GetByRefreshToken implements [repository.DeviceStore].
func (m *MockDeviceStore) GetByRefreshToken(ctx context.Context, refreshToken string) (*model.Dispositivo, error) {
	panic("unimplemented")
}

func (m *MockDeviceStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Dispositivo, error) {
	return []model.Dispositivo{}, nil
}

func (m *MockDeviceStore) GetByID(ctx context.Context, id string) (*model.Dispositivo, error) {
	return nil, nil
}

func (m *MockDeviceStore) Create(ctx context.Context, props *model.Dispositivo) error {
	return nil
}

func (m *MockDeviceStore) Update(ctx context.Context, props *model.Dispositivo) error {
	return nil
}

func (m *MockDeviceStore) CreateOrUpdate(ctx context.Context, props *model.Dispositivo) error {
	return nil
}

func (m *MockDeviceStore) Delete(ctx context.Context, id string) (*model.Dispositivo, error) {
	return nil, nil
}

// Implementa repository.ChannelStore com 7 métodos conforme canal_store.go

type MockChannelStore struct{}

func (m *MockChannelStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Canal, error) {
	return []model.Canal{}, nil
}

func (m *MockChannelStore) GetByID(ctx context.Context, id string) (*model.Canal, error) {
	return nil, nil
}

func (m *MockChannelStore) Create(ctx context.Context, props *model.Canal) error {
	return nil
}

func (m *MockChannelStore) Update(ctx context.Context, props *model.Canal) error {
	return nil
}

func (m *MockChannelStore) Delete(ctx context.Context, id_canal string) (*model.Canal, error) {
	return nil, nil
}

func (m *MockChannelStore) ListPublic(_ context.Context, _ repository.ListPublicParams) ([]model.Canal, string, string, int, error) {
    return nil, "", "", 0, nil
}

func (m *MockChannelStore) UpdateMemberCount(ctx context.Context, canalID string, delta int) error {
	return nil
}

func (m *MockChannelStore) UpsertEstadoAtual(ctx context.Context, estado *model.EstadoAtualCanal) error {
	return nil
}

// Implementa repository.UsuarioCanalStore com 8 métodos conforme usuario_canal_store.go

type MockUsuarioCanalStore struct{}

func (m *MockUsuarioCanalStore) GetAll(ctx context.Context, filter util.Filter) ([]model.UsuarioCanal, error) {
	return []model.UsuarioCanal{}, nil
}

func (m *MockUsuarioCanalStore) GetByComposedID(ctx context.Context, id_usuario string, id_canal string) (*model.UsuarioCanal, error) {
	return nil, nil
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
	return nil
}

func (m *MockUsuarioCanalStore) GetJoinedUserIDsInRoom(ctx context.Context, roomID string) ([]string, error) {
	return []string{}, nil
}

// MockEventoStore é uma implementação mock de repository.EventoStore para testes
type MockEventoStore struct {
	CheckNewFunc                   func(ctx context.Context, userID string, since model.SyncToken) (bool, error)
	GetSinceFunc                   func(ctx context.Context, userID string, since model.SyncToken) ([]model.Evento, model.SyncToken, error)
	GetMaxGlobalStreamOrderingFunc func(ctx context.Context) (int64, error)
}

func (m *MockEventoStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Evento, error) {
	return []model.Evento{}, nil
}

func (m *MockEventoStore) GetByID(ctx context.Context, id string) (*model.Evento, error) {
	return nil, nil
}

func (m *MockEventoStore) GetByTxnID(ctx context.Context, senderID, txnID string) (*model.Evento, error) {
	return nil, nil
}

func (m *MockEventoStore) Create(ctx context.Context, props *model.Evento) error {
	return nil
}

func (m *MockEventoStore) Update(ctx context.Context, props *model.Evento) error {
	return nil
}

func (m *MockEventoStore) Delete(ctx context.Context, id string) (*model.Evento, error) {
	return nil, nil
}

func (m *MockEventoStore) CheckNew(ctx context.Context, userID string, since model.SyncToken) (bool, error) {
	if m.CheckNewFunc != nil {
		return m.CheckNewFunc(ctx, userID, since)
	}
	return false, nil
}

func (m *MockEventoStore) GetSince(ctx context.Context, userID string, since model.SyncToken) ([]model.Evento, model.SyncToken, error) {
	if m.GetSinceFunc != nil {
		return m.GetSinceFunc(ctx, userID, since)
	}
	return []model.Evento{}, model.SyncToken{}, nil
}

func (m *MockEventoStore) GetMaxGlobalStreamOrdering(ctx context.Context) (int64, error) {
	if m.GetMaxGlobalStreamOrderingFunc != nil {
		return m.GetMaxGlobalStreamOrderingFunc(ctx)
	}
	return 0, nil
}

func (m *MockEventoStore) GetCurrentStateEvents(_ context.Context, _ string) ([]model.Evento, error) {
    return nil, nil
}

// MockNotifier é uma implementação mock de notifier.Notifier para testes
type MockNotifier struct {
	subscriptions map[string][]chan struct{}
}

func NewMockNotifier() *MockNotifier {
	return &MockNotifier{
		subscriptions: make(map[string][]chan struct{}),
	}
}

func (m *MockNotifier) Subscribe(userID string) chan struct{} {
	ch := make(chan struct{}, 1)
	m.subscriptions[userID] = append(m.subscriptions[userID], ch)
	return ch
}

func (m *MockNotifier) Unsubscribe(userID string, ch chan struct{}) {
	if chans, ok := m.subscriptions[userID]; ok {
		for i, c := range chans {
			if c == ch {
				m.subscriptions[userID] = append(chans[:i], chans[i+1:]...)
				close(ch)
				return
			}
		}
	}
}

func (m *MockNotifier) Notify(userID string) {
	if chans, ok := m.subscriptions[userID]; ok {
		for _, ch := range chans {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

// newTestHandler centraliza a criação do Handler com mocks, evitando
// repetição em cada teste e garantindo que todos usem os mesmos argumentos
func newTestHandler(userStore *MockUserStore, eventoStore *MockEventoStore, notif *MockNotifier) *Handler {
	if eventoStore == nil {
		eventoStore = &MockEventoStore{}
	}
	if notif == nil {
		notif = NewMockNotifier()
	}
	return NewHandler(userStore, &MockDeviceStore{}, &MockChannelStore{}, &MockUsuarioCanalStore{}, eventoStore, notif)
}

func TestGetVersionsHandler(t *testing.T) {
	h := newTestHandler(&MockUserStore{}, nil, nil)
	server := httptest.NewServer(http.HandlerFunc(h.getVersions))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("error making request to server. Err: %v", err)
	}
	defer resp.Body.Close()
	// Assertions
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK; got %v", resp.Status)
	}
	expected := "{\"versions\":[\"r0.0.5\",\"v1.18\"]}"
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body. Err: %v", err)
	}
	if expected != string(body) {
		t.Errorf("expected response body to be %v; got %v", expected, string(body))
	}
}

func TestSearchUsersHandler(t *testing.T) {
	// subtestes cobrem os três cenários relevantes da spec:
	// resultado normal, truncamento por limite, e campo obrigatório ausente

	t.Run("retorna resultados válidos", func(t *testing.T) {
		userStore := &MockUserStore{
			SearchResults: []model.Usuario{
				{ID: "@alice:example.com", Nome: "Alice", Foto: "mxc://example.com/alice"},
			},
		}
		h := newTestHandler(userStore, nil, nil)
		server := httptest.NewServer(http.HandlerFunc(h.searchUsers))
		defer server.Close()

		body := `{"search_term": "alice", "limit": 10}`
		resp, err := http.Post(server.URL, "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("error making request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200; got %v", resp.Status)
		}
		var result UserSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("error decoding response: %v", err)
		}
		if result.Limited {
			t.Error("expected limited=false")
		}
		if len(result.Results) != 1 {
			t.Fatalf("expected 1 result; got %d", len(result.Results))
		}
		if result.Results[0].UserID != "@alice:example.com" {
			t.Errorf("expected user_id @alice:example.com; got %v", result.Results[0].UserID)
		}
	})

	t.Run("limited=true quando resultados excedem o limite", func(t *testing.T) {
		// o mock retorna 2 usuários; o handler pede limit+1=2, então
		// len(usuarios) > limit → limited=true e o segundo é cortado
		userStore := &MockUserStore{
			SearchResults: []model.Usuario{
				{ID: "@a:example.com", Nome: "A"},
				{ID: "@b:example.com", Nome: "B"},
			},
		}
		h := newTestHandler(userStore, nil, nil)
		server := httptest.NewServer(http.HandlerFunc(h.searchUsers))
		defer server.Close()

		body := `{"search_term": "a", "limit": 1}`
		resp, err := http.Post(server.URL, "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("error making request: %v", err)
		}
		defer resp.Body.Close()

		var result UserSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("error decoding response: %v", err)
		}
		if !result.Limited {
			t.Error("expected limited=true")
		}
		if len(result.Results) != 1 {
			t.Errorf("expected 1 result after truncation; got %d", len(result.Results))
		}
	})

	t.Run("search_term vazio retorna 400", func(t *testing.T) {
		// search_term é obrigatório pela spec, então a ausência deve retornar Bad Request
		h := newTestHandler(&MockUserStore{}, nil, nil)
		server := httptest.NewServer(http.HandlerFunc(h.searchUsers))
		defer server.Close()

		body := `{"search_term": ""}`
		resp, err := http.Post(server.URL, "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("error making request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400; got %v", resp.Status)
		}
	})
}

func TestSyncClientHandler(t *testing.T) {
	// Helper para fazer requisições autenticadas ao syncClient
	makeSyncRequest := func(handler *Handler, since string, timeout string) (*http.Response, error) {
		url := "http://localhost/sync"
		if since != "" {
			url += "?since=" + since
		}
		if timeout != "" {
			if since != "" {
				url += "&timeout=" + timeout
			} else {
				url += "?timeout=" + timeout
			}
		}

		req := httptest.NewRequest("GET", url, nil)
		// Simula usuário autenticado adicionando userID ao context
		req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@alice:example.com"))

		w := httptest.NewRecorder()
		handler.syncClient(w, req)

		return w.Result(), nil
	}

	t.Run("initial sync: sem since token retorna eventos", func(t *testing.T) {
		// Initial sync sem since token deve retornar eventos e um novo token
		eventos := []model.Evento{
			{
				ID:               "$event1",
				Tipo:             "m.room.message",
				CanalID:          "!room:example.com",
				SenderID:         "@alice:example.com",
				Conteudo:         "{\"msgtype\":\"m.text\",\"body\":\"Hello\"}",
				OrigemServidorTS: 1234567890,
				StreamOrdering:   100,
			},
		}

		eventoStore := &MockEventoStore{
			GetSinceFunc: func(ctx context.Context, userID string, since model.SyncToken) ([]model.Evento, model.SyncToken, error) {
				return eventos, model.SyncToken{RoomEvents: 100, Receipts: 0, AccountData: 0}, nil
			},
		}

		h := newTestHandler(&MockUserStore{}, eventoStore, nil)
		resp, _ := makeSyncRequest(h, "", "")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200; got %v", resp.Status)
		}

		var result SyncClientResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("error decoding response: %v", err)
		}

		if result.NextBatch.RoomEvents != 100 {
			t.Errorf("expected next_batch.room_events=100; got %d", result.NextBatch.RoomEvents)
		}

		if len(result.Rooms.Join) != 1 {
			t.Errorf("expected 1 joined room; got %d", len(result.Rooms.Join))
		}

		if room, ok := result.Rooms.Join["!room:example.com"]; ok {
			if len(room.Timeline.Events) != 1 {
				t.Errorf("expected 1 event in timeline; got %d", len(room.Timeline.Events))
			}
		} else {
			t.Error("expected room !room:example.com in joined rooms")
		}
	})

	t.Run("incremental sync: with since token retorna apenas novos eventos", func(t *testing.T) {
		// Incremental sync com since token deve retornar apenas novos eventos
		sinceToken := model.SyncToken{RoomEvents: 50, Receipts: 0, AccountData: 0}
		novoEvento := model.Evento{
			ID:               "$event2",
			Tipo:             "m.room.message",
			CanalID:          "!room:example.com",
			SenderID:         "@bob:example.com",
			Conteudo:         "{\"msgtype\":\"m.text\",\"body\":\"Hi Alice\"}",
			OrigemServidorTS: 1234567900,
			StreamOrdering:   101,
		}

		eventoStore := &MockEventoStore{
			GetSinceFunc: func(ctx context.Context, userID string, since model.SyncToken) ([]model.Evento, model.SyncToken, error) {
				return []model.Evento{novoEvento}, model.SyncToken{RoomEvents: 101, Receipts: 0, AccountData: 0}, nil
			},
		}

		h := newTestHandler(&MockUserStore{}, eventoStore, nil)
		resp, _ := makeSyncRequest(h, sinceToken.Encode(), "")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200; got %v", resp.Status)
		}

		var result SyncClientResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("error decoding response: %v", err)
		}

		if result.NextBatch.RoomEvents != 101 {
			t.Errorf("expected next_batch.room_events=101; got %d", result.NextBatch.RoomEvents)
		}
	})

	t.Run("long-polling: sem novos eventos + timeout especificado retorna com updated token", func(t *testing.T) {
		// Sem novos eventos + timeout deve esperar até o timeout e retornar com token atualizado
		sinceToken := model.SyncToken{RoomEvents: 100, Receipts: 0, AccountData: 0}

		eventoStore := &MockEventoStore{
			CheckNewFunc: func(ctx context.Context, userID string, since model.SyncToken) (bool, error) {
				return false, nil // sem novos eventos
			},
			GetMaxGlobalStreamOrderingFunc: func(ctx context.Context) (int64, error) {
				return 105, nil // máximo global é 105
			},
		}

		notifier := NewMockNotifier()
		h := newTestHandler(&MockUserStore{}, eventoStore, notifier)

		resp, _ := makeSyncRequest(h, sinceToken.Encode(), "100")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200; got %v", resp.Status)
		}

		var result SyncClientResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("error decoding response: %v", err)
		}

		// Após timeout, token deve ser atualizado para o máximo global
		if result.NextBatch.RoomEvents != 105 {
			t.Errorf("expected next_batch.room_events=105; got %d", result.NextBatch.RoomEvents)
		}
	})

	t.Run("invalid timeout parameter: retorna 400 erro", func(t *testing.T) {
		eventoStore := &MockEventoStore{}
		h := newTestHandler(&MockUserStore{}, eventoStore, nil)

		resp, _ := makeSyncRequest(h, "", "not_a_number")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400; got %v", resp.StatusCode)
		}

		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			t.Fatalf("error decoding error response: %v", err)
		}
	})

	t.Run("zero-length eventos from eventoStore: token atualizado para max global", func(t *testing.T) {
		// Quando GetSince retorna eventos vazios, token deve ser atualizado
		sinceToken := model.SyncToken{RoomEvents: 50, Receipts: 0, AccountData: 0}

		eventoStore := &MockEventoStore{
			GetSinceFunc: func(ctx context.Context, userID string, since model.SyncToken) ([]model.Evento, model.SyncToken, error) {
				return []model.Evento{}, model.SyncToken{RoomEvents: 100, Receipts: 0, AccountData: 0}, nil
			},
		}

		h := newTestHandler(&MockUserStore{}, eventoStore, nil)
		resp, _ := makeSyncRequest(h, sinceToken.Encode(), "")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200; got %v", resp.Status)
		}

		var result SyncClientResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("error decoding response: %v", err)
		}

		// Token deve ser atualizado para o valor retornado pelo GetSince
		if result.NextBatch.RoomEvents != 100 {
			t.Errorf("expected next_batch.room_events=100; got %d", result.NextBatch.RoomEvents)
		}
	})

	t.Run("CheckNew error: retorna 500 erro", func(t *testing.T) {
		// Erro ao verificar novos eventos
		sinceToken := model.SyncToken{RoomEvents: 50, Receipts: 0, AccountData: 0}

		eventoStore := &MockEventoStore{
			CheckNewFunc: func(ctx context.Context, userID string, since model.SyncToken) (bool, error) {
				return false, errors.New("database error")
			},
		}

		h := newTestHandler(&MockUserStore{}, eventoStore, nil)
		resp, _ := makeSyncRequest(h, sinceToken.Encode(), "")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("expected 500; got %v", resp.StatusCode)
		}
	})

	t.Run("GetSince error: retorna 500 erro", func(t *testing.T) {
		// Erro ao obter eventos
		sinceToken := model.SyncToken{RoomEvents: 50, Receipts: 0, AccountData: 0}

		eventoStore := &MockEventoStore{
			GetSinceFunc: func(ctx context.Context, userID string, since model.SyncToken) ([]model.Evento, model.SyncToken, error) {
				return nil, model.SyncToken{}, errors.New("database error")
			},
		}

		h := newTestHandler(&MockUserStore{}, eventoStore, nil)
		resp, _ := makeSyncRequest(h, sinceToken.Encode(), "")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("expected 500; got %v", resp.StatusCode)
		}
	})

	t.Run("GetMaxGlobalStreamOrdering error: continua com long-polling timeout", func(t *testing.T) {
		// Erro ao obter máximo global durante long-polling timeout
		sinceToken := model.SyncToken{RoomEvents: 100, Receipts: 0, AccountData: 0}

		eventoStore := &MockEventoStore{
			CheckNewFunc: func(ctx context.Context, userID string, since model.SyncToken) (bool, error) {
				return false, nil
			},
			GetMaxGlobalStreamOrderingFunc: func(ctx context.Context) (int64, error) {
				return 0, errors.New("database error")
			},
		}

		h := newTestHandler(&MockUserStore{}, eventoStore, nil)
		resp, _ := makeSyncRequest(h, sinceToken.Encode(), "100")
		defer resp.Body.Close()

		// Mesmo com erro, deve retornar com o token original
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200; got %v", resp.StatusCode)
		}

		var result SyncClientResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("error decoding response: %v", err)
		}

		// Token deve permanecer no valor anterior já que há erro
		if result.NextBatch.RoomEvents != 100 {
			t.Errorf("expected next_batch.room_events=100; got %d", result.NextBatch.RoomEvents)
		}
	})

	t.Run("long-polling com novo evento: recebe evento antes do timeout", func(t *testing.T) {
		// Com novo evento durante long-polling, deve retornar o evento imediatamente
		sinceToken := model.SyncToken{RoomEvents: 100, Receipts: 0, AccountData: 0}
		novoEvento := model.Evento{
			ID:               "$event_new",
			Tipo:             "m.room.message",
			CanalID:          "!room:example.com",
			SenderID:         "@charlie:example.com",
			Conteudo:         "{\"msgtype\":\"m.text\",\"body\":\"New message\"}",
			OrigemServidorTS: 1234567950,
			StreamOrdering:   102,
		}

		eventoStore := &MockEventoStore{
			CheckNewFunc: func(ctx context.Context, userID string, since model.SyncToken) (bool, error) {
				return true, nil // há novos eventos
			},
			GetSinceFunc: func(ctx context.Context, userID string, since model.SyncToken) ([]model.Evento, model.SyncToken, error) {
				return []model.Evento{novoEvento}, model.SyncToken{RoomEvents: 102, Receipts: 0, AccountData: 0}, nil
			},
		}

		notifier := NewMockNotifier()
		h := newTestHandler(&MockUserStore{}, eventoStore, notifier)

		resp, _ := makeSyncRequest(h, sinceToken.Encode(), "5000")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200; got %v", resp.Status)
		}

		var result SyncClientResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("error decoding response: %v", err)
		}

		if result.NextBatch.RoomEvents != 102 {
			t.Errorf("expected next_batch.room_events=102; got %d", result.NextBatch.RoomEvents)
		}
	})

	t.Run("long-polling context cancellation: exit early", func(t *testing.T) {
		// Context cancelado deve sair do long-polling imediatamente
		sinceToken := model.SyncToken{RoomEvents: 100, Receipts: 0, AccountData: 0}

		eventoStore := &MockEventoStore{
			CheckNewFunc: func(ctx context.Context, userID string, since model.SyncToken) (bool, error) {
				return false, nil
			},
		}

		notifier := NewMockNotifier()
		h := newTestHandler(&MockUserStore{}, eventoStore, notifier)

		ctx, cancel := context.WithCancel(context.Background())
		userCtx := context.WithValue(ctx, types.UserIDKey, "@alice:example.com")

		// Cancela o contexto imediatamente
		cancel()

		req := httptest.NewRequest("GET", "http://localhost/sync?since="+sinceToken.Encode()+"&timeout=5000", nil)
		req = req.WithContext(userCtx)

		w := httptest.NewRecorder()
		h.syncClient(w, req)

		// Quando o contexto é cancelado, a função deve retornar cedo sem resposta
		// Verificamos que não houve um erro 500
		if w.Code != 0 && w.Code >= 500 {
			t.Errorf("unexpected error status: %d", w.Code)
		}
	})
}
