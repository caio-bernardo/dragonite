package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type fakeUserStore struct {
	getUser     *domain.Usuario
	getErr      error
	createUser  *domain.Usuario
	createErr   error
	lastFilter  SearchFilter
	searchUsers []domain.Profile
	searchErr   error
}

func (f *fakeUserStore) CreateUsuarioAndProfile(ctx context.Context, userProps domain.Usuario) (*domain.Usuario, error) {
	return f.createUser, f.createErr
}

func (f *fakeUserStore) GetUsuarioByID(ctx context.Context, userID string) (*domain.Usuario, error) {
	return f.getUser, f.getErr
}

func (f *fakeUserStore) GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error) {
	return nil, types.ErrNotFound
}

func (f *fakeUserStore) UpdateProfile(ctx context.Context, profile domain.Profile) error {
	return nil
}

func (f *fakeUserStore) SearchProfiles(ctx context.Context, filter SearchFilter) ([]domain.Profile, error) {
	f.lastFilter = filter
	return f.searchUsers, f.searchErr
}

func (f *fakeUserStore) AddDirectMessage(ctx context.Context, senderID, receiverID string, roomID string) error {
	return nil
}

func (f *fakeUserStore) SaveAccountData(ctx context.Context, account domain.AccountData) error {
	return nil
}
func (f *fakeUserStore) GetAccountData(ctx context.Context, userID, roomID, tipo string) (*domain.AccountData, error) {
	return nil, nil
}

type fakeDeviceStore struct {
	upserted           *domain.Dispositivo
	upsertErr          error
	deviceByID         *domain.Dispositivo
	deviceByIDErr      error
	deviceByRefresh    *domain.Dispositivo
	deviceByRefreshErr error
	updated            *domain.Dispositivo
	updateErr          error
}

func (f *fakeDeviceStore) GetDeviceByID(ctx context.Context, deviceID string) (*domain.Dispositivo, error) {
	return f.deviceByID, f.deviceByIDErr
}

func (f *fakeDeviceStore) GetDispositivoByRefreshToken(ctx context.Context, refreshToken string) (*domain.Dispositivo, error) {
	return f.deviceByRefresh, f.deviceByRefreshErr
}

func (f *fakeDeviceStore) UpsertDispositivo(ctx context.Context, device *domain.Dispositivo) error {
	f.upserted = device
	return f.upsertErr
}

func (f *fakeDeviceStore) UpdateDevice(ctx context.Context, device *domain.Dispositivo) error {
	f.updated = device
	return f.updateErr
}

func TestAuthServiceLoginSuccess(t *testing.T) {
	password := "s3cret"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	user := &domain.Usuario{ID: "@alice:example.com", SenhaHash: hash}
	userStore := &fakeUserStore{getUser: user}
	deviceStore := &fakeDeviceStore{}

	svc := NewAuthService("jwt-secret", "example.com", userStore, deviceStore)

	deviceID := uuid.NewString()
	resp, err := svc.Login(context.Background(), LoginParams{
		Indentifier: types.UserIndentifier{Type: types.IdentifierTypeUser, User: user.ID},
		Password:    password,
		DeviceID:    deviceID,
		DeviceName:  "Pixel",
		DeviceIP:    "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatalf("expected tokens to be set")
	}
	if resp.DeviceID != deviceID {
		t.Fatalf("expected device_id %s, got %s", deviceID, resp.DeviceID)
	}
	if deviceStore.upserted == nil {
		t.Fatalf("expected device to be upserted")
	}
	if deviceStore.upserted.UsuarioID != user.ID {
		t.Fatalf("expected stored device to reference user")
	}
	if deviceStore.upserted.RefreshTokenExpiresAt.Before(time.Now()) {
		t.Fatalf("expected refresh token to expire in the future")
	}
}

func TestAuthServiceLoginInvalidPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	userStore := &fakeUserStore{getUser: &domain.Usuario{ID: "@bob:example.com", SenhaHash: hash}}
	deviceStore := &fakeDeviceStore{}

	svc := NewAuthService("jwt-secret", "example.com", userStore, deviceStore)

	_, err = svc.Login(context.Background(), LoginParams{
		Indentifier: types.UserIndentifier{Type: types.IdentifierTypeUser, User: "@bob:example.com"},
		Password:    "wrong",
	})
	if !errors.Is(err, types.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthServiceRefreshExpiredToken(t *testing.T) {
	deviceStore := &fakeDeviceStore{
		deviceByRefresh: &domain.Dispositivo{
			ID:                    uuid.New(),
			UsuarioID:             "@carol:example.com",
			RefreshTokenExpiresAt: time.Now().Add(-1 * time.Hour),
		},
	}

	svc := NewAuthService("jwt-secret", "example.com", &fakeUserStore{}, deviceStore)

	_, _, err := svc.Refresh(context.Background(), "refresh-token")
	if !errors.Is(err, types.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestAuthServiceRegisterAlreadyInUse(t *testing.T) {
	userStore := &fakeUserStore{createErr: types.ErrAlreadyInUse}
	svc := NewAuthService("jwt-secret", "example.com", userStore, &fakeDeviceStore{})

	_, err := svc.Register(context.Background(), RegisterParams{Username: "alice", Senha: "pass"})
	if !errors.Is(err, types.ErrAlreadyInUse) {
		t.Fatalf("expected ErrAlreadyInUse, got %v", err)
	}
}
