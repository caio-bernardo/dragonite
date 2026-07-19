package federation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type fakeSystemStorage struct{}

func (s *fakeSystemStorage) PingDB() map[string]string {
	return map[string]string{"status": "up"}
}

func TestFederationGetVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sys := usecase.NewSystemService("example.com", "1.0.0", pub, priv, "ed25519:1", &fakeSystemStorage{})
	h := NewHandler(sys, nil, nil, nil, nil, nil, nil, nil, nil, "example.com")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/version", nil)

	h.getVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp VersionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Server.Name != "example.com" || resp.Server.Version != "1.0.0" {
		t.Fatalf("unexpected server info: %+v", resp.Server)
	}
}

func TestFederationGetServerKeySignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sys := usecase.NewSystemService("example.com", "1.0.0", pub, priv, "ed25519:1", &fakeSystemStorage{})
	h := NewHandler(sys, nil, nil, nil, nil, nil, nil, nil, nil, "example.com")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/key/v2/server", nil)

	before := time.Now()
	h.getServerKey(rec, req)
	after := time.Now()

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp ServerKeyResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ServerName != "example.com" {
		t.Fatalf("expected server_name example.com, got %s", resp.ServerName)
	}
	if resp.ValidUntilTS <= before.UnixMilli() || resp.ValidUntilTS <= after.UnixMilli() {
		t.Fatalf("expected valid_until_ts in the future")
	}

	sig := resp.Signatures["example.com"]["ed25519:1"]
	sigBytes, err := base64.RawStdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	resp.Signatures = nil
	canonical, err := util.CanonicalJSON(resp)
	if err != nil {
		t.Fatalf("canonical json: %v", err)
	}

	if !ed25519.Verify(pub, canonical, sigBytes) {
		t.Fatalf("expected signature to verify")
	}
}

// fakeUsuarioStorage implementa usecase.UsuarioStorage para testes de federation
// Apenas GetProfileByID é relevante aqui; os demais são stubs
type fakeUsuarioStorage struct {
	profiles map[string]*domain.Profile
}

func newFakeUsuarioStorage(profiles ...*domain.Profile) *fakeUsuarioStorage {
	m := &fakeUsuarioStorage{profiles: make(map[string]*domain.Profile)}
	for _, p := range profiles {
		m.profiles[p.IDUsuario] = p
	}
	return m
}

func (f *fakeUsuarioStorage) GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error) {
	p, ok := f.profiles[userID]
	if !ok {
		return nil, nil // storage retorna nil, nil quando não encontra
	}
	return p, nil
}

func (f *fakeUsuarioStorage) CreateUsuarioAndProfile(ctx context.Context, u domain.Usuario) (*domain.Usuario, error) {
	return nil, nil
}
func (f *fakeUsuarioStorage) GetUsuarioByID(ctx context.Context, userID string) (*domain.Usuario, error) {
	return nil, nil
}
func (f *fakeUsuarioStorage) UpdateProfile(ctx context.Context, p domain.Profile) error { return nil }
func (f *fakeUsuarioStorage) SearchProfiles(ctx context.Context, f2 usecase.SearchFilter) ([]domain.Profile, error) {
	return nil, nil
}
func (f *fakeUsuarioStorage) AddDirectMessage(ctx context.Context, senderID, receiverID, roomID string) error {
	return nil
}

func (f *fakeUsuarioStorage) SaveAccountData(ctx context.Context, account domain.AccountData) error {
	return nil
}
func (f *fakeUsuarioStorage) GetAccountData(ctx context.Context, userID, roomID, tipo string) (*domain.AccountData, error) {
	return nil, nil
}

func (s *fakeUsuarioStorage) GetStateAndAuthChainIDs(ctx context.Context, roomID string, eventID string) ([]string, []string, error) {
	return nil, nil, nil
}

func (s *fakeUsuarioStorage) GetGlobalAccountData(ctx context.Context, userID string) ([]domain.AccountData, error) {
	return nil, nil
}

func (s *fakeUsuarioStorage) GetAccountDataOfCanal(ctx context.Context, userID string, canalID string) ([]domain.AccountData, error) {
	return nil, nil
}

func (s *fakeUsuarioStorage) GetInviteEventsSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}

// helper para construir o handler de federation com profileService injetado
func newTestHandlerWithProfile(t *testing.T, storage *fakeUsuarioStorage) *Handler {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sys := usecase.NewSystemService("dragonite.com", "1.0.0", pub, priv, "ed25519:1", &fakeSystemStorage{})
	profileSvc := usecase.NewProfileService(storage, nil, nil, nil)
	return NewHandler(sys, nil, nil, profileSvc, nil, nil, nil, nil, nil, "example.com")
}

func TestGetProfile_MissingUserID(t *testing.T) {
	h := newTestHandlerWithProfile(t, newFakeUsuarioStorage())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/query/profile", nil)
	h.getProfile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestGetProfile_NonLocalUser(t *testing.T) {
	h := newTestHandlerWithProfile(t, newFakeUsuarioStorage())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/_matrix/federation/v1/query/profile?user_id=@alice:matrix.org", nil)
	h.getProfile(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetProfile_InvalidField(t *testing.T) {
	h := newTestHandlerWithProfile(t, newFakeUsuarioStorage())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/_matrix/federation/v1/query/profile?user_id=@alice:dragonite.com&field=invalid", nil)
	h.getProfile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestGetProfile_UserNotFound(t *testing.T) {
	h := newTestHandlerWithProfile(t, newFakeUsuarioStorage()) // store vazio

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/_matrix/federation/v1/query/profile?user_id=@alice:dragonite.com", nil)
	h.getProfile(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetProfile_FullProfile(t *testing.T) {
	displayName := "Alice"
	avatarURL := "mxc://dragonite.com/abc123"
	profile := &domain.Profile{
		IDUsuario:   "@alice:dragonite.com",
		DisplayName: &displayName,
		AvatarURL:   &avatarURL,
	}
	h := newTestHandlerWithProfile(t, newFakeUsuarioStorage(profile))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/_matrix/federation/v1/query/profile?user_id=@alice:dragonite.com", nil)
	h.getProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body domain.Profile
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.DisplayName == nil || *body.DisplayName != "Alice" {
		t.Errorf("expected displayname 'Alice', got %v", body.DisplayName)
	}
	if body.AvatarURL == nil || *body.AvatarURL != "mxc://dragonite.com/abc123" {
		t.Errorf("expected avatar_url 'mxc://dragonite.com/abc123', got %v", body.AvatarURL)
	}
}

func TestGetProfile_OnlyDisplayName(t *testing.T) {
	displayName := "Alice"
	avatarURL := "mxc://dragonite.com/abc123"
	profile := &domain.Profile{
		IDUsuario:   "@alice:dragonite.com",
		DisplayName: &displayName,
		AvatarURL:   &avatarURL,
	}
	h := newTestHandlerWithProfile(t, newFakeUsuarioStorage(profile))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/_matrix/federation/v1/query/profile?user_id=@alice:dragonite.com&field=displayname", nil)
	h.getProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body domain.Profile
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.DisplayName == nil || *body.DisplayName != "Alice" {
		t.Errorf("expected displayname 'Alice', got %v", body.DisplayName)
	}
	if body.AvatarURL != nil {
		t.Errorf("expected avatar_url absent, got %v", *body.AvatarURL)
	}
}

func TestGetProfile_OnlyAvatarURL(t *testing.T) {
	displayName := "Alice"
	avatarURL := "mxc://dragonite.com/abc123"
	profile := &domain.Profile{
		IDUsuario:   "@alice:dragonite.com",
		DisplayName: &displayName,
		AvatarURL:   &avatarURL,
	}
	h := newTestHandlerWithProfile(t, newFakeUsuarioStorage(profile))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/_matrix/federation/v1/query/profile?user_id=@alice:dragonite.com&field=avatar_url", nil)
	h.getProfile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body domain.Profile
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.AvatarURL == nil || *body.AvatarURL != "mxc://dragonite.com/abc123" {
		t.Errorf("expected avatar_url 'mxc://dragonite.com/abc123', got %v", body.AvatarURL)
	}
	if body.DisplayName != nil {
		t.Errorf("expected displayname absent, got %v", *body.DisplayName)
	}
}

// fakeDirectoryStorage implementa usecase.DirectoryStorage para testes
type fakeDirectoryStorage struct {
	entries []domain.PublicRoomEntry
	total   int
}

func (f *fakeDirectoryStorage) GetRoomIDByAlias(ctx context.Context, alias string) (string, error) {
	return "", types.ErrNotFound
}

func (f *fakeDirectoryStorage) DeleteAlias(ctx context.Context, alias string) error {
	return nil
}

func (f *fakeDirectoryStorage) SearchDirectory(_ context.Context, _ string, limit, offset int) ([]domain.PublicRoomEntry, int, error) {
	if offset >= len(f.entries) {
		return []domain.PublicRoomEntry{}, f.total, nil
	}
	result := f.entries[offset:]
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, f.total, nil
}

func newTestHandlerWithDir(t *testing.T, storage *fakeDirectoryStorage) *Handler {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sys := usecase.NewSystemService("dragonite.com", "1.0.0", pub, priv, "ed25519:1", &fakeSystemStorage{})
	dirSvc := usecase.NewDirectoryService(storage, nil, nil, nil, "example.com")
	return NewHandler(sys, nil, nil, nil, dirSvc, nil, nil, nil, nil, "example.com")
}

func TestGetPublicRooms_Empty(t *testing.T) {
	h := newTestHandlerWithDir(t, &fakeDirectoryStorage{total: 0})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/publicRooms", nil)
	h.getPublicRooms(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body domain.PublicRoomsChunck
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Chunk) != 0 {
		t.Errorf("expected empty chunk, got %d items", len(body.Chunk))
	}
	if body.NextBatch != "" {
		t.Errorf("expected no next_batch, got %q", body.NextBatch)
	}
}

func TestGetPublicRooms_WithRooms(t *testing.T) {
	name1 := "General"
	entries := []domain.PublicRoomEntry{
		{RoomID: "!room1:dragonite.com", Name: &name1, NumJoinedMembers: 10, GuestCanJoin: true, WorldReadable: true},
		{RoomID: "!room2:dragonite.com", NumJoinedMembers: 3},
	}
	h := newTestHandlerWithDir(t, &fakeDirectoryStorage{entries: entries, total: 2})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/publicRooms", nil)
	h.getPublicRooms(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body domain.PublicRoomsChunck
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Chunk) != 2 {
		t.Fatalf("expected 2 rooms, got %d", len(body.Chunk))
	}
	if body.Chunk[0].RoomID != "!room1:dragonite.com" {
		t.Errorf("expected room1 first, got %s", body.Chunk[0].RoomID)
	}
	if !body.Chunk[0].GuestCanJoin {
		t.Error("expected guest_can_join true")
	}
}

func TestGetPublicRooms_Pagination(t *testing.T) {
	entries := []domain.PublicRoomEntry{
		{RoomID: "!r1:dragonite.com", NumJoinedMembers: 3},
		{RoomID: "!r2:dragonite.com", NumJoinedMembers: 2},
		{RoomID: "!r3:dragonite.com", NumJoinedMembers: 1},
	}
	h := newTestHandlerWithDir(t, &fakeDirectoryStorage{entries: entries, total: 3})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/publicRooms?limit=2", nil)
	h.getPublicRooms(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body domain.PublicRoomsChunck
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Chunk) != 2 {
		t.Fatalf("expected 2 rooms, got %d", len(body.Chunk))
	}
	if body.NextBatch == "" {
		t.Error("expected next_batch to be set")
	}
	if body.PrevBatch != "" {
		t.Errorf("expected no prev_batch on first page, got %q", body.PrevBatch)
	}
}

func TestPostPublicRooms_BadJSON(t *testing.T) {
	h := newTestHandlerWithDir(t, &fakeDirectoryStorage{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_matrix/federation/v1/publicRooms",
		strings.NewReader("{invalid}"))
	h.postPublicRooms(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestPostPublicRooms_WithFilter(t *testing.T) {
	cheeseRoom := "Cheese Lovers"
	entries := []domain.PublicRoomEntry{
		{RoomID: "!cheese:dragonite.com", Name: &cheeseRoom, NumJoinedMembers: 10},
	}
	h := newTestHandlerWithDir(t, &fakeDirectoryStorage{entries: entries, total: 1})

	body, _ := json.Marshal(PublicRoomsRequest{
		Filter: &PublicRoomsFilter{GenericSearchTerm: "cheese"},
		Limit:  10,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_matrix/federation/v1/publicRooms",
		strings.NewReader(string(body)))
	h.postPublicRooms(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp domain.PublicRoomsChunck
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Chunk) != 1 {
		t.Fatalf("expected 1 room, got %d", len(resp.Chunk))
	}
	if resp.Chunk[0].RoomID != "!cheese:dragonite.com" {
		t.Errorf("expected cheese room, got %s", resp.Chunk[0].RoomID)
	}
}

func TestPostPublicRooms_EmptyBody(t *testing.T) {
	entries := []domain.PublicRoomEntry{
		{RoomID: "!r1:dragonite.com", NumJoinedMembers: 5},
	}
	h := newTestHandlerWithDir(t, &fakeDirectoryStorage{entries: entries, total: 1})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_matrix/federation/v1/publicRooms",
		strings.NewReader("{}"))
	h.postPublicRooms(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp domain.PublicRoomsChunck
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Chunk) != 1 {
		t.Fatalf("expected 1 room, got %d", len(resp.Chunk))
	}
}

// Fakes para FederationService

type fakeFedCanalStore struct {
	canal               *domain.Canal
	joinRule            string
	servers             []string
	membership          string
	upsertedMemberships []fedUpsertMembershipRecord
}

type fedUpsertMembershipRecord struct {
	RoomID, UserID, Membership, EventID string
}

func (f *fakeFedCanalStore) GetByID(_ context.Context, _ string) (*domain.Canal, error) {
	return f.canal, nil
}
func (f *fakeFedCanalStore) GetJoinRule(_ context.Context, _ string) (string, error) {
	return f.joinRule, nil
}
func (f *fakeFedCanalStore) GetCanalParticipatingServers(_ context.Context, _ string) ([]string, error) {
	return f.servers, nil
}
func (f *fakeFedCanalStore) UpsertMembership(_ context.Context, roomID, userID, membership, eventID string) error {
	f.upsertedMemberships = append(f.upsertedMemberships, fedUpsertMembershipRecord{roomID, userID, membership, eventID})
	return nil
}
func (f *fakeFedCanalStore) UpsertCurrentState(_ context.Context, _, _, _, _ string) error {
	return nil
}
func (f *fakeFedCanalStore) Create(_ context.Context, _, _ string) (*domain.Canal, error) {
	return nil, nil
}
func (f *fakeFedCanalStore) GetUserJoinedRooms(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeFedCanalStore) GetUserMembership(_ context.Context, _, _ string) (string, error) {
	return f.membership, nil
}
func (f *fakeFedCanalStore) GetUserMembershipRecord(_ context.Context, _, _ string) (string, bool, error) {
	return "", false, nil
}
func (f *fakeFedCanalStore) GetStateEventID(_ context.Context, _, _, _ string) (string, bool) {
	return "", false
}
func (f *fakeFedCanalStore) GetAllPublic(_ context.Context, _, _ int) ([]domain.Canal, error) {
	return nil, nil
}
func (f *fakeFedCanalStore) UpdateForwardExtremities(_ context.Context, _ string, _ string, _ []string) error {
	return nil
}
func (f *fakeFedCanalStore) GetForwardExtremities(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeFedCanalStore) SaveAlias(_ context.Context, _, _ string) error { return nil }
func (f *fakeFedCanalStore) GetUserLeftRooms(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

type fakeFedEventoStore struct {
	stateEvents []domain.Evento
}

func (f *fakeFedEventoStore) GetCurrentStateEvents(_ context.Context, _ string) ([]domain.Evento, error) {
	if f.stateEvents == nil {
		return []domain.Evento{}, nil
	}
	return f.stateEvents, nil
}
func (f *fakeFedEventoStore) SaveEvento(_ context.Context, _ *domain.Evento) error { return nil }
func (f *fakeFedEventoStore) GetSince(_ context.Context, _ string, _ domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}
func (f *fakeFedEventoStore) GetMaxDepthFromEventos(_ context.Context, _ []string) (int64, error) {
	return 0, nil
}
func (f *fakeFedEventoStore) GetMaxStreamOrdering(_ context.Context) (int64, error) {
	return 0, nil
}
func (f *fakeFedEventoStore) GetEvento(_ context.Context, _ string) (*domain.Evento, error) {
	return nil, nil
}
func (f *fakeFedEventoStore) GetEventsSince(_ context.Context, _ string, _ int, _ []string) ([]domain.Evento, error) {
	return nil, nil
}
func (f *fakeFedEventoStore) CheckEventoExists(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (f *fakeFedEventoStore) GetRoomMessagesHistory(ctx context.Context, roomID string, fromToken int64, dir string, limit int) ([]domain.Evento, error) {
	return nil, nil
}

func (f *fakeFedEventoStore) GetMissingEvents(ctx context.Context, roomID string, earliestEvents, latestEvents []string, limit int, minDepth int64) ([]domain.Evento, error) {
	return nil, nil
}

func (f *fakeFedEventoStore) GetStateAndAuthChainIDs(ctx context.Context, roomID string, eventID string) ([]string, []string, error) {
	return nil, nil, nil
}

func (f *fakeFedEventoStore) SaveReceipt(ctx context.Context, userID, roomID, receiptType, eventID string, ts int64) error {
	return nil
}

func (f *fakeFedEventoStore) GetEventsOfCanalSince(ctx context.Context, userID string, roomID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}

func (f *fakeFedEventoStore) GetEventsOfCanalSinceLeft(ctx context.Context, userID string, roomID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}

func (f *fakeFedEventoStore) GetStateAndAuthChainEvents(ctx context.Context, roomID string, userID string) ([]domain.Evento, []domain.Evento, error) {
	return nil, nil, nil
}

func (f *fakeFedEventoStore) GetRoomMemberEvents(ctx context.Context, roomID string) ([]domain.Evento, error) {
	return nil, nil
}
func (f *fakeFedEventoStore) SaveTypingState(ctx context.Context, roomID, userID string, isTyping bool, expiresAt int64) error {
	return nil
}

type fakeFedWorkUnit struct{}

func (f *fakeFedWorkUnit) Execute(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

// newMuxServer cria um httptest.Server com o handler registrado no padrão correto.
// Necessário para testes de handlers que usam r.PathValue()
func newMuxServer(pattern string, h http.HandlerFunc) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc(pattern, h)
	return httptest.NewServer(mux)
}

// signJoinRequest assina um SendJoinRequest com a chave privada fornecida.
func signJoinRequest(t *testing.T, privKey ed25519.PrivateKey, keyID string, req SendJoinRequest) SendJoinRequest {
	t.Helper()
	payload := map[string]interface{}{
		"content":          req.Content,
		"origin":           req.Origin,
		"origin_server_ts": req.OriginServerTS,
		"room_id":          req.RoomID,
		"sender":           req.Sender,
		"state_key":        req.StateKey,
		"type":             req.Type,
	}
	canonical, err := util.CanonicalJSON(payload)
	if err != nil {
		t.Fatalf("signJoinRequest: %v", err)
	}
	sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(privKey, canonical))
	req.Signatures = map[string]map[string]string{
		req.Origin: {keyID: sig},
	}
	return req
}

func newTestHandlerWithFed(t *testing.T, canalStore *fakeFedCanalStore, eventoStore *fakeFedEventoStore) *Handler {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sys := usecase.NewSystemService("dragonite.com", "1.0.0", pub, priv, "ed25519:1", &fakeSystemStorage{})
	fedSvc := usecase.NewFederationService("dragonite.com", "ed25519:1", priv, canalStore, eventoStore, &fakeFedWorkUnit{}, nil, nil)
	return NewHandler(sys, fedSvc, nil, nil, nil, nil, nil, nil, nil, "example.com")
}

// Testes makeJoin

func TestMakeJoin_RoomNotFound(t *testing.T) {
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: nil}, &fakeFedEventoStore{})
	server := newMuxServer("GET /_matrix/federation/v1/make_join/{roomId}/{userId}", h.makeJoin)
	defer server.Close()

	resp, err := http.Get(server.URL + "/_matrix/federation/v1/make_join/%21naoexiste%3Adriagonite.com/%40bob%3Aremote.com?ver=11")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestMakeJoin_IncompatibleVersion(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal, joinRule: "public"}, &fakeFedEventoStore{})
	server := newMuxServer("GET /_matrix/federation/v1/make_join/{roomId}/{userId}", h.makeJoin)
	defer server.Close()

	resp, err := http.Get(server.URL + "/_matrix/federation/v1/make_join/%21room%3Adriagonite.com/%40bob%3Aremote.com?ver=1&ver=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestMakeJoin_RoomNotPublic(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal, joinRule: "invite"}, &fakeFedEventoStore{})
	server := newMuxServer("GET /_matrix/federation/v1/make_join/{roomId}/{userId}", h.makeJoin)
	defer server.Close()

	resp, err := http.Get(server.URL + "/_matrix/federation/v1/make_join/%21room%3Adriagonite.com/%40bob%3Aremote.com?ver=11")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestMakeJoin_HappyPath(t *testing.T) {
	userID := "@bob:remote.com"
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal, joinRule: "public"}, &fakeFedEventoStore{})
	server := newMuxServer("GET /_matrix/federation/v1/make_join/{roomId}/{userId}", h.makeJoin)
	defer server.Close()

	resp, err := http.Get(server.URL + "/_matrix/federation/v1/make_join/%21room%3Adriagonite.com/%40bob%3Aremote.com?ver=11")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body MakeJoinResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.RoomVersion != "11" {
		t.Errorf("expected room_version 11, got %q", body.RoomVersion)
	}
	if body.Event.Type != "m.room.member" {
		t.Errorf("expected type m.room.member, got %q", body.Event.Type)
	}
	if body.Event.Sender != userID {
		t.Errorf("expected sender %q, got %q", userID, body.Event.Sender)
	}
	if body.Event.Content.Membership != "join" {
		t.Errorf("expected membership join, got %q", body.Event.Content.Membership)
	}
}

// Testes sendJoin

func TestSendJoin_BadJSON(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}", h.sendJoin)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_join/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader("{invalid}"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendJoin_InvalidType(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}", h.sendJoin)
	defer server.Close()

	body, _ := json.Marshal(SendJoinRequest{
		Type: "m.room.message", Sender: "@bob:remote.com", StateKey: "@bob:remote.com",
		Origin: "remote.com", Content: MembershipContent{Membership: "join"},
	})
	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_join/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendJoin_SenderNotEqualStateKey(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}", h.sendJoin)
	defer server.Close()

	body, _ := json.Marshal(SendJoinRequest{
		Type: "m.room.member", Sender: "@bob:remote.com", StateKey: "@alice:remote.com",
		Origin: "remote.com", Content: MembershipContent{Membership: "join"},
	})
	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_join/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendJoin_SenderNotFromOrigin(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}", h.sendJoin)
	defer server.Close()

	body, _ := json.Marshal(SendJoinRequest{
		Type: "m.room.member", Sender: "@bob:outro.com", StateKey: "@bob:outro.com",
		Origin: "remote.com", Content: MembershipContent{Membership: "join"},
	})
	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_join/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendJoin_InvalidSignature(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal, joinRule: "public"}, &fakeFedEventoStore{})

	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	h.keyFetcher = func(_ string) (string, ed25519.PublicKey, error) {
		return "ed25519:remote", wrongPub, nil
	}

	server := newMuxServer("PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}", h.sendJoin)
	defer server.Close()

	_, realPriv, _ := ed25519.GenerateKey(rand.Reader)
	joinReq := signJoinRequest(t, realPriv, "ed25519:remote", SendJoinRequest{
		Type: "m.room.member", Sender: "@bob:remote.com", StateKey: "@bob:remote.com",
		Origin: "remote.com", RoomID: "!room:dragonite.com", EventID: "$e:remote.com",
		OriginServerTS: time.Now().UnixMilli(), Content: MembershipContent{Membership: "join"},
	})
	body, _ := json.Marshal(joinReq)
	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_join/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendJoin_HappyPath(t *testing.T) {
	remotePub, remotePriv, _ := ed25519.GenerateKey(rand.Reader)
	remoteKeyID := "ed25519:remote"
	remoteOrigin := "remote.com"

	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	eventoStore := &fakeFedEventoStore{}
	canalStore := &fakeFedCanalStore{
		canal:    canal,
		joinRule: "public",
		servers:  []string{"dragonite.com"},
	}

	h := newTestHandlerWithFed(t, canalStore, eventoStore)
	h.keyFetcher = func(_ string) (string, ed25519.PublicKey, error) {
		return remoteKeyID, remotePub, nil
	}

	server := newMuxServer("PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}", h.sendJoin)
	defer server.Close()

	joinReq := signJoinRequest(t, remotePriv, remoteKeyID, SendJoinRequest{
		Type:           "m.room.member",
		Sender:         "@bob:" + remoteOrigin,
		StateKey:       "@bob:" + remoteOrigin,
		Origin:         remoteOrigin,
		RoomID:         canal.ID,
		EventID:        "$join:remote.com",
		OriginServerTS: time.Now().UnixMilli(),
		Content:        MembershipContent{Membership: "join"},
	})
	body, _ := json.Marshal(joinReq)

	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_join/%21room%3Adriagonite.com/%24join%3Aremote.com",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, bodyBytes)
	}

	var respBody SendJoinResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if respBody.State == nil {
		t.Error("expected state to be non-nil")
	}
	if respBody.AuthChain == nil {
		t.Error("expected auth_chain to be non-nil")
	}
}

// Testes putInvite
func TestPutInvite_BadJSON(t *testing.T) {
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/invite/{roomId}/{eventId}", h.putInvite)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/invite/%21room%3Aremote.com/%24invite%3Aremote.com",
		strings.NewReader("{invalid}"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestPutInvite_UserNotLocal(t *testing.T) {
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/invite/{roomId}/{eventId}", h.putInvite)
	defer server.Close()

	// state_key is set to @bob:remote.com rather than local server (dragonite.com)
	eventMap := map[string]interface{}{
		"type":      "m.room.member",
		"sender":    "@alice:remote.com",
		"state_key": "@bob:remote.com",
		"content":   map[string]interface{}{"membership": "invite"},
	}
	eventBytes, _ := json.Marshal(eventMap)
	body, _ := json.Marshal(InviteRequest{Event: eventBytes})

	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/invite/%21room%3Aremote.com/%24invite%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestPutInvite_InvalidSignature(t *testing.T) {
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{}, &fakeFedEventoStore{})

	// Server responds with a different pub key
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	h.keyFetcher = func(_ string) (string, ed25519.PublicKey, error) {
		return "ed25519:remote", wrongPub, nil
	}

	server := newMuxServer("PUT /_matrix/federation/v2/invite/{roomId}/{eventId}", h.putInvite)
	defer server.Close()

	eventMap := map[string]interface{}{
		"type":      "m.room.member",
		"sender":    "@alice:remote.com",
		"state_key": "@bob:dragonite.com",
		"content":   map[string]interface{}{"membership": "invite"},
		"signatures": map[string]interface{}{
			"remote.com": map[string]interface{}{"ed25519:remote": "Badsig/XXX"},
		},
	}
	eventBytes, _ := json.Marshal(eventMap)
	body, _ := json.Marshal(InviteRequest{Event: eventBytes})

	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/invite/%21room%3Aremote.com/%24invite%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden { // Spec demands forbidden for sig fails
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestPutInvite_HappyPath(t *testing.T) {
	remotePub, remotePriv, _ := ed25519.GenerateKey(rand.Reader)
	remoteKeyID := "ed25519:remote"
	remoteOrigin := "remote.com"

	canal := &domain.Canal{ID: "!room:remote.com", Versao: "11"}
	eventoStore := &fakeFedEventoStore{}
	canalStore := &fakeFedCanalStore{
		canal:    canal,
		joinRule: "invite",
		servers:  []string{"remote.com"},
	}

	h := newTestHandlerWithFed(t, canalStore, eventoStore)
	h.keyFetcher = func(_ string) (string, ed25519.PublicKey, error) {
		return remoteKeyID, remotePub, nil
	}

	server := newMuxServer("PUT /_matrix/federation/v2/invite/{roomId}/{eventId}", h.putInvite)
	defer server.Close()

	eventMap := map[string]any{
		"type":      "m.room.member",
		"sender":    "@alice:" + remoteOrigin,
		"state_key": "@bob:dragonite.com",
		"room_id":   canal.ID,
		"content":   map[string]interface{}{"membership": "invite"},
	}

	canonical, _ := util.CanonicalJSON(eventMap)
	sigBytes := ed25519.Sign(remotePriv, canonical)
	eventMap["signatures"] = map[string]interface{}{
		remoteOrigin: map[string]interface{}{
			remoteKeyID: base64.RawStdEncoding.EncodeToString(sigBytes),
		},
	}

	eventRaw, _ := json.Marshal(eventMap)
	inviteReq := InviteRequest{
		RoomVersion: "11",
		Event:       eventRaw,
	}
	body, _ := json.Marshal(inviteReq)

	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/invite/%21room%3Aremote.com/%24invite%3Aremote.com",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, bodyBytes)
	}

	var respBody InviteResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var respEventMap map[string]interface{}
	if err := json.Unmarshal(respBody.Event, &respEventMap); err != nil {
		t.Fatalf("failed to unmarshal response event: %v", err)
	}

	sigsRaw, ok := respEventMap["signatures"]
	if !ok || sigsRaw == nil {
		t.Fatalf("expected 'signatures' key in response event, got payload: %s", string(respBody.Event))
	}

	sigs, ok := sigsRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("expected 'signatures' to be a map, got %T", sigsRaw)
	}

	if _, ok := sigs["dragonite.com"]; !ok {
		t.Errorf("expected response to be signed by dragonite.com, got sigs: %v", sigs)
	}
}

func TestPutInvite_HappyPath_UpsertsInviteeMembership(t *testing.T) {
	remotePub, remotePriv, _ := ed25519.GenerateKey(rand.Reader)
	remoteKeyID := "ed25519:remote"
	remoteOrigin := "remote.com"
	invitee := "@bob:dragonite.com"

	canal := &domain.Canal{ID: "!room:remote.com", Versao: "11"}
	eventoStore := &fakeFedEventoStore{}
	canalStore := &fakeFedCanalStore{
		canal:    canal,
		joinRule: "invite",
		servers:  []string{"remote.com"},
	}

	h := newTestHandlerWithFed(t, canalStore, eventoStore)
	h.keyFetcher = func(_ string) (string, ed25519.PublicKey, error) {
		return remoteKeyID, remotePub, nil
	}

	server := newMuxServer("PUT /_matrix/federation/v2/invite/{roomId}/{eventId}", h.putInvite)
	defer server.Close()

	eventMap := map[string]any{
		"type":      "m.room.member",
		"sender":    "@alice:" + remoteOrigin,
		"state_key": invitee,
		"room_id":   canal.ID,
		"content":   map[string]interface{}{"membership": "invite"},
	}

	canonical, _ := util.CanonicalJSON(eventMap)
	sigBytes := ed25519.Sign(remotePriv, canonical)
	eventMap["signatures"] = map[string]interface{}{
		remoteOrigin: map[string]interface{}{
			remoteKeyID: base64.RawStdEncoding.EncodeToString(sigBytes),
		},
	}

	eventRaw, _ := json.Marshal(eventMap)
	body, _ := json.Marshal(InviteRequest{RoomVersion: "11", Event: eventRaw})

	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/invite/%21room%3Aremote.com/%24invite%3Aremote.com",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, bodyBytes)
	}

	if len(canalStore.upsertedMemberships) != 1 {
		t.Fatalf("expected 1 upserted membership, got %d", len(canalStore.upsertedMemberships))
	}
	got := canalStore.upsertedMemberships[0]
	if got.UserID != invitee {
		t.Errorf("expected invitee %s to receive the invite membership, got %s (regressão do bug sender/state_key)", invitee, got.UserID)
	}
	if got.Membership != "invite" {
		t.Errorf("expected membership 'invite', got %s", got.Membership)
	}
}

// Testes makeLeave

func TestMakeLeave_RoomNotFound(t *testing.T) {
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: nil}, &fakeFedEventoStore{})
	server := newMuxServer("GET /_matrix/federation/v1/make_leave/{roomId}/{userId}", h.makeLeave)
	defer server.Close()

	resp, err := http.Get(server.URL + "/_matrix/federation/v1/make_leave/%21naoexiste%3Adriagonite.com/%40bob%3Aremote.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestMakeLeave_UserNotMember(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	// membership is "" by default — user is not a member
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal}, &fakeFedEventoStore{})
	server := newMuxServer("GET /_matrix/federation/v1/make_leave/{roomId}/{userId}", h.makeLeave)
	defer server.Close()

	resp, err := http.Get(server.URL + "/_matrix/federation/v1/make_leave/%21room%3Adriagonite.com/%40bob%3Aremote.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestMakeLeave_HappyPath(t *testing.T) {
	userID := "@bob:remote.com"
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal, membership: "join"}, &fakeFedEventoStore{})
	server := newMuxServer("GET /_matrix/federation/v1/make_leave/{roomId}/{userId}", h.makeLeave)
	defer server.Close()

	resp, err := http.Get(server.URL + "/_matrix/federation/v1/make_leave/%21room%3Adriagonite.com/%40bob%3Aremote.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body MakeLeaveResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.RoomVersion != "11" {
		t.Errorf("expected room_version 11, got %q", body.RoomVersion)
	}
	if body.Event.Type != "m.room.member" {
		t.Errorf("expected type m.room.member, got %q", body.Event.Type)
	}
	if body.Event.Sender != userID {
		t.Errorf("expected sender %q, got %q", userID, body.Event.Sender)
	}
	if body.Event.Content.Membership != "leave" {
		t.Errorf("expected membership leave, got %q", body.Event.Content.Membership)
	}
}

// Testes sendLeave

func signLeaveRequest(t *testing.T, privKey ed25519.PrivateKey, keyID string, req SendLeaveRequest) SendLeaveRequest {
	t.Helper()
	payload := map[string]interface{}{
		"content":          req.Content,
		"origin":           req.Origin,
		"origin_server_ts": req.OriginServerTS,
		"room_id":          req.RoomID,
		"sender":           req.Sender,
		"state_key":        req.StateKey,
		"type":             req.Type,
	}
	canonical, err := util.CanonicalJSON(payload)
	if err != nil {
		t.Fatalf("signLeaveRequest: %v", err)
	}
	sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(privKey, canonical))
	req.Signatures = map[string]map[string]string{
		req.Origin: {keyID: sig},
	}
	return req
}

func TestSendLeave_BadJSON(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}", h.sendLeave)
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_leave/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader("{invalid}"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendLeave_InvalidType(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}", h.sendLeave)
	defer server.Close()

	body, _ := json.Marshal(SendLeaveRequest{
		Type: "m.room.message", Sender: "@bob:remote.com", StateKey: "@bob:remote.com",
		Origin: "remote.com", Content: MembershipContent{Membership: "leave"},
	})
	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_leave/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendLeave_MembershipNotLeave(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}", h.sendLeave)
	defer server.Close()

	body, _ := json.Marshal(SendLeaveRequest{
		Type: "m.room.member", Sender: "@bob:remote.com", StateKey: "@bob:remote.com",
		Origin: "remote.com", Content: MembershipContent{Membership: "join"},
	})
	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_leave/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendLeave_SenderNotEqualStateKey(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}", h.sendLeave)
	defer server.Close()

	body, _ := json.Marshal(SendLeaveRequest{
		Type: "m.room.member", Sender: "@bob:remote.com", StateKey: "@alice:remote.com",
		Origin: "remote.com", Content: MembershipContent{Membership: "leave"},
	})
	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_leave/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendLeave_SenderNotFromOrigin(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal}, &fakeFedEventoStore{})
	server := newMuxServer("PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}", h.sendLeave)
	defer server.Close()

	body, _ := json.Marshal(SendLeaveRequest{
		Type: "m.room.member", Sender: "@bob:outro.com", StateKey: "@bob:outro.com",
		Origin: "remote.com", Content: MembershipContent{Membership: "leave"},
	})
	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_leave/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendLeave_InvalidSignature(t *testing.T) {
	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	h := newTestHandlerWithFed(t, &fakeFedCanalStore{canal: canal, membership: "join"}, &fakeFedEventoStore{})

	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	h.keyFetcher = func(_ string) (string, ed25519.PublicKey, error) {
		return "ed25519:remote", wrongPub, nil
	}

	server := newMuxServer("PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}", h.sendLeave)
	defer server.Close()

	_, realPriv, _ := ed25519.GenerateKey(rand.Reader)
	leaveReq := signLeaveRequest(t, realPriv, "ed25519:remote", SendLeaveRequest{
		Type: "m.room.member", Sender: "@bob:remote.com", StateKey: "@bob:remote.com",
		Origin: "remote.com", RoomID: "!room:dragonite.com", EventID: "$e:remote.com",
		OriginServerTS: time.Now().UnixMilli(), Content: MembershipContent{Membership: "leave"},
	})
	body, _ := json.Marshal(leaveReq)
	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_leave/%21room%3Adriagonite.com/%24e%3Aremote.com",
		strings.NewReader(string(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSendLeave_HappyPath(t *testing.T) {
	remotePub, remotePriv, _ := ed25519.GenerateKey(rand.Reader)
	remoteKeyID := "ed25519:remote"
	remoteOrigin := "remote.com"

	canal := &domain.Canal{ID: "!room:dragonite.com", Versao: "11"}
	canalStore := &fakeFedCanalStore{
		canal:      canal,
		membership: "join",
		servers:    []string{"dragonite.com"},
	}

	h := newTestHandlerWithFed(t, canalStore, &fakeFedEventoStore{})
	h.keyFetcher = func(_ string) (string, ed25519.PublicKey, error) {
		return remoteKeyID, remotePub, nil
	}

	server := newMuxServer("PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}", h.sendLeave)
	defer server.Close()

	leaveReq := signLeaveRequest(t, remotePriv, remoteKeyID, SendLeaveRequest{
		Type:           "m.room.member",
		Sender:         "@bob:" + remoteOrigin,
		StateKey:       "@bob:" + remoteOrigin,
		Origin:         remoteOrigin,
		RoomID:         canal.ID,
		EventID:        "$leave:remote.com",
		OriginServerTS: time.Now().UnixMilli(),
		Content:        MembershipContent{Membership: "leave"},
	})
	body, _ := json.Marshal(leaveReq)

	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/_matrix/federation/v2/send_leave/%21room%3Adriagonite.com/%24leave%3Aremote.com",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, bodyBytes)
	}

	var respBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(respBody) != 0 {
		t.Errorf("expected empty response body, got %v", respBody)
	}
}

// fakeFileStorage e fakeMidiaStorage implementam usecase.FileStorage e usecase.MidiaStorage para testar o proxy de mídia via federação

type fakeFileStorage struct {
	content []byte
}

func (f *fakeFileStorage) Upload(_ context.Context, _ string, _ io.Reader, _ int64, _ string) error {
	return nil
}
func (f *fakeFileStorage) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	if f.content == nil {
		return nil, fmt.Errorf("not found")
	}
	return io.NopCloser(bytes.NewReader(f.content)), nil
}
func (f *fakeFileStorage) Delete(_ context.Context, _ string) error { return nil }

type fakeMidiaStorage struct {
	midia *domain.Midia
}

func (f *fakeMidiaStorage) SaveMidia(_ context.Context, _ *domain.Midia) error { return nil }
func (f *fakeMidiaStorage) GetMidiaByID(_ context.Context, _, _ string) (*domain.Midia, error) {
	return f.midia, nil
}

func newTestHandlerWithMedia(t *testing.T, mediaSvc *usecase.MediaService) *Handler {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sys := usecase.NewSystemService("dragonite.com", "1.0.0", pub, priv, "ed25519:1", &fakeSystemStorage{})
	return NewHandler(sys, nil, nil, nil, nil, mediaSvc, nil, nil, nil, "example.com")
}

// Testes getMediaDownload

func TestGetMediaDownload_NotFound(t *testing.T) {
	mediaSvc := usecase.NewMediaService("dragonite.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 0, nil)
	h := newTestHandlerWithMedia(t, mediaSvc)

	server := newMuxServer("GET /_matrix/federation/v1/media/download/{mediaId}", h.getMediaDownload)
	defer server.Close()

	resp, err := http.Get(server.URL + "/_matrix/federation/v1/media/download/abc123")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestGetMediaDownload_HappyPath(t *testing.T) {
	fileContent := []byte("hello world")
	fileStore := &fakeFileStorage{content: fileContent}
	midiaStore := &fakeMidiaStorage{midia: &domain.Midia{
		IDMidia:     "abc123",
		Origin:      "dragonite.com",
		ContentType: "text/plain",
		SizeBytes:   int64(len(fileContent)),
		UploadName:  "hello.txt",
	}}
	mediaSvc := usecase.NewMediaService("dragonite.com", fileStore, midiaStore, 0, nil)
	h := newTestHandlerWithMedia(t, mediaSvc)

	server := newMuxServer("GET /_matrix/federation/v1/media/download/{mediaId}", h.getMediaDownload)
	defer server.Close()

	resp, err := http.Get(server.URL + "/_matrix/federation/v1/media/download/abc123")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("expected multipart response, got %q (err=%v)", resp.Header.Get("Content-Type"), err)
	}

	mr := multipart.NewReader(resp.Body, params["boundary"])

	if _, err := mr.NextPart(); err != nil {
		t.Fatalf("failed to read metadata part: %v", err)
	}

	filePart, err := mr.NextPart()
	if err != nil {
		t.Fatalf("failed to read file part: %v", err)
	}
	fileBytes, err := io.ReadAll(filePart)
	if err != nil {
		t.Fatalf("failed to read file content: %v", err)
	}
	if string(fileBytes) != string(fileContent) {
		t.Errorf("expected file content %q, got %q", fileContent, fileBytes)
	}
	if filePart.Header.Get("Content-Type") != "text/plain" {
		t.Errorf("expected content-type text/plain, got %q", filePart.Header.Get("Content-Type"))
	}
}
