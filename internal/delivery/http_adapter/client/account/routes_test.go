package account

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

// mock storage implementing only account data methods
type mockUsuarioStore struct {
	store map[string]domain.AccountData
}

func newMockUsuarioStore() *mockUsuarioStore {
	return &mockUsuarioStore{store: make(map[string]domain.AccountData)}
}

func (m *mockUsuarioStore) SaveAccountData(ctx context.Context, account domain.AccountData) error {
	key := account.IDUsuario + "|" + account.IDCanal + "|" + account.Tipo
	m.store[key] = account
	return nil
}

func (m *mockUsuarioStore) GetAccountData(ctx context.Context, userID, roomID, tipo string) (*domain.AccountData, error) {
	key := userID + "|" + roomID + "|" + tipo
	acct, ok := m.store[key]
	if !ok {
		return nil, nil
	}
	return &acct, nil
}

// other methods to satisfy interface — stubs
func (m *mockUsuarioStore) CreateUsuarioAndProfile(ctx context.Context, userProps domain.Usuario) (*domain.Usuario, error) {
	return nil, nil
}
func (m *mockUsuarioStore) GetUsuarioByID(ctx context.Context, userID string) (*domain.Usuario, error) {
	return nil, nil
}
func (m *mockUsuarioStore) GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error) {
	return nil, nil
}
func (m *mockUsuarioStore) UpdateProfile(ctx context.Context, profile domain.Profile) error {
	return nil
}
func (m *mockUsuarioStore) SearchProfiles(ctx context.Context, filter usecase.SearchFilter) ([]domain.Profile, error) {
	return nil, nil
}
func (m *mockUsuarioStore) AddDirectMessage(ctx context.Context, senderID, receiverID string, roomID string) error {
	return nil
}

func (m *mockUsuarioStore) GetStateAndAuthChainIDs(ctx context.Context, roomID string, eventID string) ([]string, []string, error) {
	return nil, nil, nil
}

func (m *mockUsuarioStore) GetGlobalAccountData(ctx context.Context, userID string) ([]domain.AccountData, error) {
	return nil, nil
}

func (m *mockUsuarioStore) GetAccountDataOfCanal(ctx context.Context, userID string, canalID string) ([]domain.AccountData, error) {
	return nil, nil
}

func (m *mockUsuarioStore) GetInviteEventsSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}

func TestWhoami(t *testing.T) {
	store := newMockUsuarioStore()
	accSvc := usecase.NewAccountService(store)
	h := NewHandler(accSvc)

	// simula o que o TokenBearerMiddleware faria após validar o token
	ctx := context.WithValue(context.Background(), types.UserIDKey, "@alice:example.org")
	ctx = context.WithValue(ctx, types.DeviceIDKey, "ABC1234")

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/account/whoami", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	h.whoami(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp WhoamiResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.UserID != "@alice:example.org" {
		t.Fatalf("unexpected user_id: %s", resp.UserID)
	}
	if resp.DeviceID != "ABC1234" {
		t.Fatalf("unexpected device_id: %s", resp.DeviceID)
	}
	if resp.IsGuest {
		t.Fatalf("expected is_guest false by default")
	}
}

func TestWhoamiMissingUserID(t *testing.T) {
	store := newMockUsuarioStore()
	accSvc := usecase.NewAccountService(store)
	h := NewHandler(accSvc)

	// contexto sem user_id, simulando um bug/uso indevido sem passar pelo middleware
	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/account/whoami", nil)
	rec := httptest.NewRecorder()

	h.whoami(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	var errResp httputil.MatrixErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if errResp.ErrCode != httputil.M_UNKNOWN_TOKEN {
		t.Fatalf("expected M_UNKNOWN_TOKEN, got %s", errResp.ErrCode)
	}
}

func TestPutAndGetUserAccountData(t *testing.T) {
	store := newMockUsuarioStore()
	accSvc := usecase.NewAccountService(store)
	h := NewHandler(accSvc)

	// prepare request
	body := bytes.NewBufferString(`{"foo":"bar"}`)
	req := httptest.NewRequest(http.MethodPut, "/_matrix/client/v3/user/@alice:ex/account_data/com.example.test", body)
	// chamando o handler diretamente (sem passar pelo mux), então os path values
	// precisam ser setados manualmente
	req.SetPathValue("userId", "@alice:ex")
	req.SetPathValue("type", "com.example.test")
	rec := httptest.NewRecorder()

	h.putUserAccountData(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// now GET
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/user/@alice:ex/account_data/com.example.test", nil)
	req.SetPathValue("userId", "@alice:ex")
	req.SetPathValue("type", "com.example.test")

	h.getUserAccountData(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on get, got %d: %s", rec.Code, rec.Body.String())
	}

	var acct domain.AccountData
	if err := json.NewDecoder(rec.Body).Decode(&acct); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if acct.Tipo != "com.example.test" {
		t.Fatalf("unexpected tipo: %s", acct.Tipo)
	}
}
