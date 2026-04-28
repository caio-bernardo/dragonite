package client

import (
	"bytes"
	"context"
	"encoding/json" 
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/util"
)

// MockUserStore is a mock implementation of repository.UserStore for testing
type MockUserStore struct{
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

func (m *MockChannelStore) ListPublic(ctx context.Context, limit int, sinceToken string) ([]model.Canal, string, error) {
	return []model.Canal{}, "", nil
}

func (m *MockChannelStore) UpdateMemberCount(ctx context.Context, canalID string, delta int) error {
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

// newTestHandler centraliza a criação do Handler com mocks, evitando
// repetição em cada teste e garantindo que todos usem os mesmos 4 argumentos
func newTestHandler(userStore *MockUserStore) *Handler {
	return NewHandler(userStore, &MockDeviceStore{}, &MockChannelStore{}, &MockUsuarioCanalStore{})
}

func TestGetVersionsHandler(t *testing.T) {
	h := newTestHandler(&MockUserStore{})
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
		h := newTestHandler(userStore)
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
		h := newTestHandler(userStore)
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
		h := newTestHandler(&MockUserStore{})
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
