package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/util"
)

// MockUserStore is a mock implementation of repository.UserStore for testing
type MockUserStore struct{}

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

func TestGetVersionsHandler(t *testing.T) {
	userStore := &MockUserStore{}
	deviceStore := &MockDeviceStore{}
	h := NewHandler(userStore, deviceStore)
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
