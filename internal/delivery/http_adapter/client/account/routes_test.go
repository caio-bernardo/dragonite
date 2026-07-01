package account

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/domain"
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

func TestPutAndGetUserAccountData(t *testing.T) {
	store := newMockUsuarioStore()
	accSvc := usecase.NewAccountService(store)
	h := NewHandler(accSvc)

	// prepare request
	body := bytes.NewBufferString(`{"foo":"bar"}`)
	req := httptest.NewRequest(http.MethodPut, "/_matrix/client/v3/user/@alice:ex/account_data/com.example.test", body)
	// call handler directly
	rec := httptest.NewRecorder()

	h.putUserAccountData(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// now GET
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/_matrix/client/v3/user/@alice:ex/account_data/com.example.test", nil)

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
