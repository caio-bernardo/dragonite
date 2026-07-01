package auth

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
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type authUserStore struct {
	user      *domain.Usuario
	err       error
	createErr error
}

func (s *authUserStore) CreateUsuarioAndProfile(ctx context.Context, userProps domain.Usuario) (*domain.Usuario, error) {
	return nil, s.createErr
}

func (s *authUserStore) GetUsuarioByID(ctx context.Context, userID string) (*domain.Usuario, error) {
	return s.user, s.err
}

func (s *authUserStore) GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error) {
	return nil, types.ErrNotFound
}

func (s *authUserStore) UpdateProfile(ctx context.Context, profile domain.Profile) error {
	return nil
}

func (s *authUserStore) SearchProfiles(ctx context.Context, filter usecase.SearchFilter) ([]domain.Profile, error) {
	return nil, nil
}

func (s *authUserStore) AddDirectMessage(ctx context.Context, senderID, receiverID string, roomID string) error {
	return nil
}

func (s *authUserStore) SaveAccountData(ctx context.Context, account domain.AccountData) error {
	return nil
}
func (s *authUserStore) GetAccountData(ctx context.Context, userID, roomID, tipo string) (*domain.AccountData, error) {
	return nil, nil
}

type authDeviceStore struct {
	upserted *domain.Dispositivo
}

func (s *authDeviceStore) GetDeviceByID(ctx context.Context, deviceID string) (*domain.Dispositivo, error) {
	return nil, types.ErrNotFound
}

func (s *authDeviceStore) GetDispositivoByRefreshToken(ctx context.Context, refreshToken string) (*domain.Dispositivo, error) {
	return nil, types.ErrNotFound
}

func (s *authDeviceStore) UpsertDispositivo(ctx context.Context, device *domain.Dispositivo) error {
	s.upserted = device
	return nil
}

func (s *authDeviceStore) UpdateDevice(ctx context.Context, device *domain.Dispositivo) error {
	return nil
}

func TestPostLoginSuccess(t *testing.T) {
	password := "passw0rd"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	user := &domain.Usuario{ID: "@alice:example.com", SenhaHash: hash}
	authSvc := usecase.NewAuthService("jwt-secret", "example.com", &authUserStore{user: user}, &authDeviceStore{})
	h := NewHandler(authSvc)

	deviceID := uuid.NewString()
	payload := LoginRequest{
		Type:       "m.login.password",
		Identifier: types.UserIndentifier{Type: types.IdentifierTypeUser, User: user.ID},
		Password:   password,
		DeviceID:   deviceID,
	}
	body, _ := json.Marshal(payload)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/login", bytes.NewReader(body))

	h.postLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp LoginReponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatalf("expected tokens to be set")
	}
	if resp.DeviceID != deviceID {
		t.Fatalf("expected device_id to match request")
	}
}

func TestPostRegisterUserInUse(t *testing.T) {
	userStore := &authUserStore{createErr: types.ErrAlreadyInUse}
	authSvc := usecase.NewAuthService("jwt-secret", "example.com", userStore, &authDeviceStore{})
	h := NewHandler(authSvc)

	payload := RegisterRequest{Username: "alice", Password: "pass"}
	body, _ := json.Marshal(payload)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/register", bytes.NewReader(body))

	h.postRegister(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	var resp struct {
		ErrCode string `json:"errcode"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.ErrCode != "M_USER_IN_USE" {
		t.Fatalf("expected M_USER_IN_USE, got %s", resp.ErrCode)
	}
}
