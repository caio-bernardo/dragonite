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
	"strings"
	"bytes"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/repository"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
	_ "github.com/joho/godotenv/autoload"
)

// --- Mock UserStore ---

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

// --- Mock CanalStore ---

type mockCanalStore struct {
	canais []model.Canal
}

func newMockCanalStore(canais ...model.Canal) *mockCanalStore {
	return &mockCanalStore{canais: canais}
}

func (m *mockCanalStore) ListPublic(_ context.Context, params repository.ListPublicParams) ([]model.Canal, string, string, int, error) {
	// Filtra canais públicos com optional search term
	filtered := make([]model.Canal, 0)
	for _, c := range m.canais {
		if !c.IsPublic {
			continue
		}
		if params.SearchTerm != "" {
			term := strings.ToLower(params.SearchTerm)
			if !strings.Contains(strings.ToLower(c.Nome), term) &&
				!strings.Contains(strings.ToLower(c.Descricao), term) {
				continue
			}
		}
		filtered = append(filtered, c)
	}

	total := len(filtered)

	offset := 0
	if params.SinceToken != "" {
		fmt.Sscanf(params.SinceToken, "%d", &offset)
	}
	if offset > len(filtered) {
		offset = len(filtered)
	}
	filtered = filtered[offset:]

	nextBatch := ""
	if params.Limit > 0 && len(filtered) > params.Limit {
		filtered = filtered[:params.Limit]
		nextBatch = fmt.Sprintf("%d", offset+params.Limit)
	}

	prevBatch := ""
	if offset > 0 && params.Limit > 0 {
		if prev := offset - params.Limit; prev >= 0 {
			prevBatch = fmt.Sprintf("%d", prev)
		}
	}

	return filtered, nextBatch, prevBatch, total, nil
}

func (m *mockCanalStore) GetAll(_ context.Context, _ util.Filter) ([]model.Canal, error)             { return nil, nil }
func (m *mockCanalStore) GetByID(_ context.Context, _ string) (*model.Canal, error)                  { return nil, nil }
func (m *mockCanalStore) Create(_ context.Context, _ *model.Canal) error                             { return nil }
func (m *mockCanalStore) Update(_ context.Context, _ *model.Canal) error                             { return nil }
func (m *mockCanalStore) Delete(_ context.Context, _ string) (*model.Canal, error)                   { return nil, nil }
func (m *mockCanalStore) UpdateMemberCount(_ context.Context, _ string, _ int) error                 { return nil }
func (m *mockCanalStore) UpsertEstadoAtual(_ context.Context, _ *model.EstadoAtualCanal) error       { return nil }

// Helpers

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

func NewTestHandler(userStore *mockUserStore, canalStore *mockCanalStore) *Handler {
    config := MockConfig()
    return NewHandler(&config, userStore, canalStore)
}

// --- Testes existentes ---

func TestFederationVersion(t *testing.T) {
	h := NewTestHandler(newMockUserStore(), newMockCanalStore())
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
	h := NewTestHandler(newMockUserStore(), newMockCanalStore())
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
	h := NewTestHandler(newMockUserStore(), newMockCanalStore())
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
	h := NewTestHandler(newMockUserStore(), newMockCanalStore())
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
	h := NewTestHandler(newMockUserStore(), newMockCanalStore())
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
	h := NewTestHandler(newMockUserStore(), newMockCanalStore()) // store vazio
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
	h := NewTestHandler(newMockUserStore(usuario), newMockCanalStore())
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
	h := NewTestHandler(newMockUserStore(usuario), newMockCanalStore())
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
	h := NewTestHandler(newMockUserStore(usuario), newMockCanalStore())
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

// --- Testes getPublicRooms ---

func TestGetPublicRooms_Empty(t *testing.T) {
	h := NewTestHandler(newMockUserStore(), newMockCanalStore())
	server := httptest.NewServer(http.HandlerFunc(h.getPublicRooms))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body PublicRoomsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Chunk) != 0 {
		t.Errorf("expected empty chunk, got %d items", len(body.Chunk))
	}
}

func TestGetPublicRooms_WithRooms(t *testing.T) {
	roomType := "m.space"
	canais := []model.Canal{
		{
			ID: "!room1:dragonite.com", Nome: "General", Descricao: "General chat",
			IsPublic: true, JoinRules: "public", GuestAccess: "can_join",
			HistoryVisibility: "world_readable", MemberCount: 10, RoomType: &roomType,
		},
		{
			ID: "!room2:dragonite.com", Nome: "Off-Topic", IsPublic: true,
			JoinRules: "public", GuestAccess: "forbidden",
			HistoryVisibility: "shared", MemberCount: 3,
		},
	}
	h := NewTestHandler(newMockUserStore(), newMockCanalStore(canais...))
	server := httptest.NewServer(http.HandlerFunc(h.getPublicRooms))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body PublicRoomsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Chunk) != 2 {
		t.Fatalf("expected 2 rooms, got %d", len(body.Chunk))
	}
	// Verifica conversão de campos
	first := body.Chunk[0]
	if first.RoomID != "!room1:dragonite.com" {
		t.Errorf("expected room1, got %s", first.RoomID)
	}
	if !first.GuestCanJoin {
		t.Error("expected guest_can_join true")
	}
	if !first.WorldReadable {
		t.Error("expected world_readable true")
	}
	if first.RoomType != "m.space" {
		t.Errorf("expected room_type 'm.space', got %q", first.RoomType)
	}
	// Segunda sala: guest_can_join e world_readable devem ser false
	second := body.Chunk[1]
	if second.GuestCanJoin {
		t.Error("expected guest_can_join false")
	}
	if second.WorldReadable {
		t.Error("expected world_readable false")
	}
}

func TestGetPublicRooms_Pagination(t *testing.T) {
	canais := []model.Canal{
		{ID: "!r1:dragonite.com", Nome: "Room 1", IsPublic: true, MemberCount: 3},
		{ID: "!r2:dragonite.com", Nome: "Room 2", IsPublic: true, MemberCount: 2},
		{ID: "!r3:dragonite.com", Nome: "Room 3", IsPublic: true, MemberCount: 1},
	}
	h := NewTestHandler(newMockUserStore(), newMockCanalStore(canais...))
	server := httptest.NewServer(http.HandlerFunc(h.getPublicRooms))
	defer server.Close()

	resp, err := http.Get(server.URL + "?limit=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var body PublicRoomsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Chunk) != 2 {
		t.Fatalf("expected 2 rooms, got %d", len(body.Chunk))
	}
	if body.NextBatch == "" {
		t.Error("expected next_batch to be set")
	}
	if body.PrevBatch != "" {
		t.Errorf("expected prev_batch absent na primeira página, got %q", body.PrevBatch)
	}
}

// --- Testes postPublicRooms ---

func TestPostPublicRooms_BadJSON(t *testing.T) {
	h := NewTestHandler(newMockUserStore(), newMockCanalStore())
	server := httptest.NewServer(http.HandlerFunc(h.postPublicRooms))
	defer server.Close()

	resp, err := http.Post(server.URL, "application/json", bytes.NewBufferString("{invalid json}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestPostPublicRooms_WithFilter(t *testing.T) {
	canais := []model.Canal{
		{ID: "!cheese:dragonite.com", Nome: "Cheese Lovers", IsPublic: true, MemberCount: 10},
		{ID: "!code:dragonite.com", Nome: "Coding Talk", IsPublic: true, MemberCount: 5},
	}
	h := NewTestHandler(newMockUserStore(), newMockCanalStore(canais...))
	server := httptest.NewServer(http.HandlerFunc(h.postPublicRooms))
	defer server.Close()

	reqBody, _ := json.Marshal(PublicRoomsRequest{
		Filter: &PublicRoomsFilter{GenericSearchTerm: "cheese"},
	})
	resp, err := http.Post(server.URL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body PublicRoomsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Chunk) != 1 {
		t.Fatalf("expected 1 room após filtro, got %d", len(body.Chunk))
	}
	if body.Chunk[0].RoomID != "!cheese:dragonite.com" {
		t.Errorf("expected cheese room, got %s", body.Chunk[0].RoomID)
	}
}

func TestPostPublicRooms_EmptyBody(t *testing.T) {
	canais := []model.Canal{
		{ID: "!r1:dragonite.com", Nome: "Room 1", IsPublic: true, MemberCount: 5},
	}
	h := NewTestHandler(newMockUserStore(), newMockCanalStore(canais...))
	server := httptest.NewServer(http.HandlerFunc(h.postPublicRooms))
	defer server.Close()

	// Body vazio é válido — equivale a POST sem filtros
	resp, err := http.Post(server.URL, "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body PublicRoomsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Chunk) != 1 {
		t.Fatalf("expected 1 room, got %d", len(body.Chunk))
	}
}