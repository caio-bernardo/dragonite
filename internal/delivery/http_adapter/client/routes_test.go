package client

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

type clientUserStore struct {
	profiles []domain.Profile
}

func (c *clientUserStore) CreateUsuarioAndProfile(ctx context.Context, userProps domain.Usuario) (*domain.Usuario, error) {
	return nil, nil
}

func (c *clientUserStore) GetUsuarioByID(ctx context.Context, userID string) (*domain.Usuario, error) {
	return nil, nil
}

func (c *clientUserStore) GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error) {
	return nil, nil
}

func (c *clientUserStore) UpdateProfile(ctx context.Context, profile domain.Profile) error {
	return nil
}

func (c *clientUserStore) SearchProfiles(ctx context.Context, filter usecase.SearchFilter) ([]domain.Profile, error) {
	return c.profiles, nil
}

func (c *clientUserStore) AddDirectMessage(ctx context.Context, senderID, receiverID string, roomID string) error {
	return nil
}

func (c *clientUserStore) SaveAccountData(ctx context.Context, account domain.AccountData) error {
	return nil
}

func (c *clientUserStore) GetAccountData(ctx context.Context, userID, roomID, tipo string) (*domain.AccountData, error) {
	return nil, nil
}

func (s *clientUserStore) GetStateAndAuthChainIDs(ctx context.Context, roomID string, eventID string) ([]string, []string, error) {
	return nil, nil, nil
}

func (s *clientUserStore) GetGlobalAccountData(ctx context.Context, userID string) ([]domain.AccountData, error) {
	return nil, nil
}

func (s *clientUserStore) GetAccountDataOfCanal(ctx context.Context, userID string, canalID string) ([]domain.AccountData, error) {
	return nil, nil
}

func (s *clientUserStore) GetInviteEventsSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}

type clientCanalStore struct {
	joinedRooms []string
}

func (c *clientCanalStore) Create(ctx context.Context, roomID, userID string) (*domain.Canal, error) {
	return nil, nil
}

func (c *clientCanalStore) GetByID(ctx context.Context, canalID string) (*domain.Canal, error) {
	return nil, nil
}

func (c *clientCanalStore) GetJoinRule(ctx context.Context, roomID string) (string, error) {
	return "", nil
}

func (c *clientCanalStore) GetUserJoinedRooms(ctx context.Context, userID string) ([]string, error) {
	return c.joinedRooms, nil
}

func (c *clientCanalStore) GetUserMembership(ctx context.Context, roomID, userID string) (string, error) {
	return "", nil
}

func (c *clientCanalStore) GetStateEventID(ctx context.Context, canalID string, stateType, stateKey string) (string, bool) {
	return "", false
}

func (c *clientCanalStore) UpsertMembership(ctx context.Context, roomID, userID, membership, id_evento string) error {
	return nil
}

func (c *clientCanalStore) UpsertCurrentState(ctx context.Context, canalID, stateType, stateKey, eventID string) error {
	return nil
}

func (c *clientCanalStore) GetAllPublic(ctx context.Context, offset, limit int) ([]domain.Canal, error) {
	return nil, nil
}

func (c *clientCanalStore) UpdateForwardExtremities(ctx context.Context, canalID string, eventID string, extremeties []string) error {
	return nil
}

func (c *clientCanalStore) GetForwardExtremities(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}

func (c *clientCanalStore) SaveAlias(ctx context.Context, roomID, fullAlias string) error {
	return nil
}

func (c *clientCanalStore) GetCanalParticipatingServers(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}

func (c *clientCanalStore) GetUserLeftRooms(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}

func TestGetVersions(t *testing.T) {
	h := NewHandler("example.com", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/versions", nil)

	h.getVersions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp SupportedVersionsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	found := false
	for _, v := range resp.Versions {
		if v == "v1.18" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected v1.18 in versions")
	}
}

func TestGetPushRules(t *testing.T) {
	h := NewHandler("example.com", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/pushrules/", nil)

	h.getPushRules(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp PushRulesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Global == nil {
		t.Fatalf("expected global key to be present in response")
	}
}

func TestUploadFilterOK(t *testing.T) {
	h := NewHandler("example.com", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	body := bytes.NewBufferString(`{"room":{"timeline":{"limit":10}}}`)
	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/user/@alice:example.com/filter", body)
	req.SetPathValue("userId", "@alice:example.com")
	rec := httptest.NewRecorder()

	h.uploadFilter(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp FilterUploadResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.FilterID == "" {
		t.Fatalf("expected filter_id to be set")
	}
}

func TestUploadFilterInvalidJSON(t *testing.T) {
	h := NewHandler("example.com", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	body := bytes.NewBufferString(`{invalid`)
	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/user/@alice:example.com/filter", body)
	req.SetPathValue("userId", "@alice:example.com")
	rec := httptest.NewRecorder()

	h.uploadFilter(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	var resp struct {
		ErrCode string `json:"errcode"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.ErrCode != "M_BAD_JSON" {
		t.Fatalf("expected M_BAD_JSON, got %s", resp.ErrCode)
	}
}

func TestGetCapabilities(t *testing.T) {
	h := NewHandler("example.com", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/capabilities", nil)

	h.getCapabilities(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp CapabilitiesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Capabilities.RoomVersions.Default != "11" {
		t.Fatalf("expected default room version 11, got %s", resp.Capabilities.RoomVersions.Default)
	}
	if stability, ok := resp.Capabilities.RoomVersions.Available["11"]; !ok || stability != "stable" {
		t.Fatalf("expected room version 11 to be stable, got %v", resp.Capabilities.RoomVersions.Available)
	}
}

func TestSearchUsersOK(t *testing.T) {
	display := "Alice"
	avatar := "mxc://example.com/a"
	userStore := &clientUserStore{profiles: []domain.Profile{
		{IDUsuario: "@alice:example.com", DisplayName: &display, AvatarURL: &avatar},
		{IDUsuario: "@alex:example.com", DisplayName: &display, AvatarURL: &avatar},
	}}
	canalStore := &clientCanalStore{joinedRooms: []string{"!room1:example.com"}}
	dirService := usecase.NewDirectoryService(nil, userStore, canalStore)

	h := NewHandler("example.com", nil, nil, dirService, nil, nil, nil, nil, nil, nil, nil, nil)

	body := bytes.NewBufferString(`{"search_term":"al","limit":1}`)
	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/user_directory/search", body)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@searcher:example.com"))
	rec := httptest.NewRecorder()

	h.searchUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp UserSearchResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Limited {
		t.Fatalf("expected limited=true when more than limit results are returned")
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	if resp.Results[0].UserID == "" {
		t.Fatalf("expected user_id to be set")
	}
}

func TestSearchUsersMissingSearchTerm(t *testing.T) {
	dirService := usecase.NewDirectoryService(nil, &clientUserStore{}, &clientCanalStore{})
	h := NewHandler("example.com", nil, nil, dirService, nil, nil, nil, nil, nil, nil, nil, nil)

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/user_directory/search", body)
	req = req.WithContext(context.WithValue(req.Context(), types.UserIDKey, "@searcher:example.com"))
	rec := httptest.NewRecorder()

	h.searchUsers(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	var resp struct {
		ErrCode string `json:"errcode"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.ErrCode != "M_BAD_JSON" {
		t.Fatalf("expected M_BAD_JSON, got %s", resp.ErrCode)
	}
}
