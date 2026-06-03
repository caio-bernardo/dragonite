package federation

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
	_ "github.com/joho/godotenv/autoload"
)

type mockUserStore struct {
	users map[string]*model.Usuario
}

func newMockUserStore(users ...*model.Usuario) *mockUserStore {
	m := &mockUserStore{users: make(map[string]*model.Usuario)}
	for _, u := range users {
		m.users[u.ID] = u
	}
	return m
}

func (m *mockUserStore) GetNameAndPhotoByID(_ context.Context, id string) (*model.Usuario, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	return u, nil
}

// Stubs para satisfazer a interface UserStore
func (m *mockUserStore) GetAll(_ context.Context, _ util.Filter) ([]model.Usuario, error)          { return nil, nil }
func (m *mockUserStore) GetByID(_ context.Context, _ string) (*model.Usuario, error)               { return nil, nil }
func (m *mockUserStore) GetByLocal(_ context.Context, _ string) (*model.Usuario, error)            { return nil, nil }
func (m *mockUserStore) Create(_ context.Context, _ *model.Usuario) error                          { return nil }
func (m *mockUserStore) Update(_ context.Context, _ *model.Usuario) error                          { return nil }
func (m *mockUserStore) Delete(_ context.Context, _ string) (*model.Usuario, error)                { return nil, nil }
func (m *mockUserStore) Search(_ context.Context, _ string, _ int) ([]model.Usuario, error)        { return nil, nil }
func (m *mockUserStore) ClearProfileKey(_ context.Context, _ string, _ string) error               { return nil }
func (m *mockUserStore) UpdateProfileKey(_ context.Context, _ string, _ string, _ string) error    { return nil }


func MockConfig() types.ServerConfig {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	return types.ServerConfig{
		ServerName: "dragonite.com",
		Version:    "1.0.0",
		KeyID:      "ed25519:1.0.0",
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}

func NewTestHandler(userStore *mockUserStore) *Handler {
    config := MockConfig()
    return NewHandler(&config, userStore)
}

func TestFederationVersion(t *testing.T) {
	h := NewTestHandler(newMockUserStore())
	server := httptest.NewServer(http.HandlerFunc(h.getVersion))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	expectedName := h.config.ServerName
	expectBody := fmt.Sprintf(`{"server":{"name":"%s","version":"%s"}}`, expectedName, "1.0.0")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != expectBody {
		t.Errorf("expected body %s, got %s", expectBody, string(body))
	}
}

func TestGetKeyServer(t *testing.T) {
	h := NewTestHandler(newMockUserStore())
	server := httptest.NewServer(http.HandlerFunc(h.getServerKey))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	var body ServerKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
        t.Fatal(err)
    }

    // Verifica campos estáticos
    if body.ServerName != h.config.ServerName {
        t.Errorf("expected server_name %q, got %q", h.config.ServerName, body.ServerName)
    }

    verifyKey, ok := body.VerifyKeys[h.config.KeyID]
    if !ok {
        t.Fatalf("expected verify key %q not found", h.config.KeyID)
    }
    expectedKey := base64.RawStdEncoding.EncodeToString(h.config.PublicKey)
    if verifyKey.Key != expectedKey {
        t.Errorf("expected key %q, got %q", expectedKey, verifyKey.Key)
    }

    // Verifica que valid_until_ts é aproximadamente 1 ano (margem de 5s)
    expectedTS := time.Now().Add(365 * 24 * time.Hour).UnixMilli()
    diff := body.ValidUntilTS - expectedTS
    if diff < -5000 || diff > 5000 {
        t.Errorf("valid_until_ts %d fora do esperado (~%d)", body.ValidUntilTS, expectedTS)
    }

    // Verifica a assinatura criptograficamente:
    // extrai a assinatura, reconstrói o JSON sem ela, e valida
    sig, ok := body.Signatures[h.config.ServerName][h.config.KeyID]
    if !ok {
        t.Fatal("assinatura não encontrada na resposta")
    }
    sigBytes, err := base64.RawStdEncoding.DecodeString(sig)
    if err != nil {
        t.Fatalf("erro ao decodificar assinatura: %v", err)
    }

    // Remove as signatures para reconstruir o payload que foi assinado
    bodyWithoutSig := body
    bodyWithoutSig.Signatures = nil
    canonical, err := util.CanonicalJSON(bodyWithoutSig)
    if err != nil {
        t.Fatalf("erro ao gerar canonical JSON: %v", err)
    }

    if !ed25519.Verify(h.config.PublicKey, canonical, sigBytes) {
        t.Error("assinatura inválida")
    }
}

// Testes do getProfile 

func TestGetProfile_MissingUserID(t *testing.T) {
	h := NewTestHandler(newMockUserStore())
	server := httptest.NewServer(http.HandlerFunc(h.getProfile))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestGetProfile_NonLocalUser(t *testing.T) {
	h := NewTestHandler(newMockUserStore())
	server := httptest.NewServer(http.HandlerFunc(h.getProfile))
	defer server.Close()

	resp, err := http.Get(server.URL + "?user_id=@alice:matrix.org")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestGetProfile_InvalidField(t *testing.T) {
	h := NewTestHandler(newMockUserStore())
	server := httptest.NewServer(http.HandlerFunc(h.getProfile))
	defer server.Close()

	resp, err := http.Get(server.URL + "?user_id=@alice:dragonite.com&field=invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestGetProfile_UserNotFound(t *testing.T) {
	h := NewTestHandler(newMockUserStore()) // store vazio
	server := httptest.NewServer(http.HandlerFunc(h.getProfile))
	defer server.Close()

	resp, err := http.Get(server.URL + "?user_id=@alice:dragonite.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestGetProfile_FullProfile(t *testing.T) {
	usuario := &model.Usuario{
		ID:   "@alice:dragonite.com",
		Nome: "Alice",
		Foto: "mxc://dragonite.com/abc123",
	}
	h := NewTestHandler(newMockUserStore(usuario))
	server := httptest.NewServer(http.HandlerFunc(h.getProfile))
	defer server.Close()

	resp, err := http.Get(server.URL + "?user_id=@alice:dragonite.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body model.ProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.DisplayName != "Alice" {
		t.Errorf("expected displayname 'Alice', got '%s'", body.DisplayName)
	}
	if body.AvatarURL != "mxc://dragonite.com/abc123" {
		t.Errorf("expected avatar_url 'mxc://dragonite.com/abc123', got '%s'", body.AvatarURL)
	}
}

func TestGetProfile_OnlyDisplayName(t *testing.T) {
	usuario := &model.Usuario{
		ID:   "@alice:dragonite.com",
		Nome: "Alice",
		Foto: "mxc://dragonite.com/abc123",
	}
	h := NewTestHandler(newMockUserStore(usuario))
	server := httptest.NewServer(http.HandlerFunc(h.getProfile))
	defer server.Close()

	resp, err := http.Get(server.URL + "?user_id=@alice:dragonite.com&field=displayname")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body model.ProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.DisplayName != "Alice" {
		t.Errorf("expected displayname 'Alice', got '%s'", body.DisplayName)
	}
	if body.AvatarURL != "" {
		t.Errorf("expected avatar_url to be absent, got '%s'", body.AvatarURL)
	}
}

func TestGetProfile_OnlyAvatarURL(t *testing.T) {
	usuario := &model.Usuario{
		ID:   "@alice:dragonite.com",
		Nome: "Alice",
		Foto: "mxc://dragonite.com/abc123",
	}
	h := NewTestHandler(newMockUserStore(usuario))
	server := httptest.NewServer(http.HandlerFunc(h.getProfile))
	defer server.Close()

	resp, err := http.Get(server.URL + "?user_id=@alice:dragonite.com&field=avatar_url")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body model.ProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.AvatarURL != "mxc://dragonite.com/abc123" {
		t.Errorf("expected avatar_url 'mxc://dragonite.com/abc123', got '%s'", body.AvatarURL)
	}
	if body.DisplayName != "" {
		t.Errorf("expected displayname to be absent, got '%s'", body.DisplayName)
	}
}