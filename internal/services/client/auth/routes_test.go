package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
	"golang.org/x/crypto/bcrypt"
)

// MockUserStore is a mock implementation of repository.UserStore for testing
type MockUserStore struct {
	userByLocal    *model.Usuario
	userByLocalErr error
}

func (m *MockUserStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Usuario, error) {
	return []model.Usuario{}, nil
}

func (m *MockUserStore) GetByID(ctx context.Context, id string) (*model.Usuario, error) {
	return nil, nil
}

func (m *MockUserStore) GetByLocal(ctx context.Context, localpart string) (*model.Usuario, error) {
	return m.userByLocal, m.userByLocalErr
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
type MockDeviceStore struct {
	createOrUpdateCalled bool
	createOrUpdateDevice *model.Dispositivo
	createOrUpdateErr    error
}

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
	m.createOrUpdateCalled = true
	m.createOrUpdateDevice = props
	return m.createOrUpdateErr
}

func (m *MockDeviceStore) Delete(ctx context.Context, id string) (*model.Dispositivo, error) {
	return nil, nil
}

func TestGetLoginFlows(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)
	server := httptest.NewServer(http.HandlerFunc(h.getLogin))
	defer server.Close()
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("error making request to server. Err: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status OK; got %v", resp.Status)
	}

	expected := `{"flows":[{"type":"m.login.password"}]}`
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body. Err: %v", err)
	}
	if expected != string(body) {
		t.Errorf("expected response body to be %v; got %v", expected, string(body))
	}

}

func TestPostLogin_Success(t *testing.T) {
	originalKey := JWTSecretKey
	JWTSecretKey = []byte("test-secret")
	defer func() {
		JWTSecretKey = originalKey
	}()

	password := "password"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	mockUserStore := MockUserStore{
		userByLocal: &model.Usuario{
			ID:        "@user:example.com",
			LocalPart: "user",
			Senha:     string(hashedPassword),
		},
	}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	payload := LoginRequest{
		Type: string(types.AuthenticationTypePassword),
		Identifier: types.UserIndentifier{
			Type: types.IdentifierTypeUser,
			User: "user",
		},
		Password:                 password,
		DeviceID:                 "DEVICE",
		InitialDeviceDisplayName: "My Phone",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/login", bytes.NewBuffer(body))
	req.RemoteAddr = "203.0.113.9:1234"
	rr := httptest.NewRecorder()

	h.postLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status OK; got %v", rr.Code)
	}

	var response LoginReponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.AccessToken == "" {
		t.Fatalf("expected access_token to be set")
	}
	if response.RefreshToken == "" {
		t.Fatalf("expected refresh_token to be set")
	}
	if response.DeviceID != payload.DeviceID {
		t.Fatalf("expected device_id %q; got %q", payload.DeviceID, response.DeviceID)
	}
	if response.UserID != mockUserStore.userByLocal.ID {
		t.Fatalf("expected user_id %q; got %q", mockUserStore.userByLocal.ID, response.UserID)
	}
	if response.ExpireMS == nil || *response.ExpireMS <= 0 {
		t.Fatalf("expected expire_ms to be set with positive value")
	}

	if !mockDeviceStore.createOrUpdateCalled {
		t.Fatalf("expected device store to be called")
	}
	if mockDeviceStore.createOrUpdateDevice == nil {
		t.Fatalf("expected device to be passed to device store")
	}
	if mockDeviceStore.createOrUpdateDevice.ID != payload.DeviceID {
		t.Fatalf("expected device ID %q; got %q", payload.DeviceID, mockDeviceStore.createOrUpdateDevice.ID)
	}
	if mockDeviceStore.createOrUpdateDevice.Nome != payload.InitialDeviceDisplayName {
		t.Fatalf("expected device name %q; got %q", payload.InitialDeviceDisplayName, mockDeviceStore.createOrUpdateDevice.Nome)
	}
	if mockDeviceStore.createOrUpdateDevice.RefreshToken != response.RefreshToken {
		t.Fatalf("expected stored refresh token to match response refresh token")
	}
	if mockDeviceStore.createOrUpdateDevice.UltimoIPVisto != "203.0.113.9" {
		t.Fatalf("expected ultimo_ip_visto to be 203.0.113.9; got %q", mockDeviceStore.createOrUpdateDevice.UltimoIPVisto)
	}
	if mockDeviceStore.createOrUpdateDevice.UltimoTimestampVisto.IsZero() {
		t.Fatalf("expected ultimo_timestamp_visto to be set")
	}
	if time.Since(mockDeviceStore.createOrUpdateDevice.UltimoTimestampVisto) > 2*time.Second {
		t.Fatalf("expected ultimo_timestamp_visto to be recent")
	}
}

func TestPostLogin_BadJSON(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/login", bytes.NewBufferString("{invalid-json"))
	rr := httptest.NewRecorder()

	h.postLogin(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status BadRequest; got %v", rr.Code)
	}

	var response types.ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.ErrCode != types.M_BAD_JSON {
		t.Fatalf("expected errcode %q; got %q", types.M_BAD_JSON, response.ErrCode)
	}
}

func TestPostLogin_UnsupportedAuthType(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	payload := LoginRequest{
		Type: "m.login.token",
		Identifier: types.UserIndentifier{
			Type: types.IdentifierTypeUser,
			User: "user",
		},
		Password: "password",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/login", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	h.postLogin(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status BadRequest; got %v", rr.Code)
	}

	var response types.ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.ErrCode != types.M_UNRECOGNIZED {
		t.Fatalf("expected errcode %q; got %q", types.M_UNRECOGNIZED, response.ErrCode)
	}
}

func TestPostLogin_EmptyBody(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	req := &http.Request{
		Method: http.MethodPost,
		Body:   nil,
	}
	rr := httptest.NewRecorder()

	h.postLogin(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status BadRequest; got %v", rr.Code)
	}

	var response types.ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.ErrCode != types.M_NOT_JSON {
		t.Fatalf("expected errcode %q; got %q", types.M_NOT_JSON, response.ErrCode)
	}
}

func TestPostRefresh_NotImplementedYet(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Post(server.URL+"/_matrix/client/v3/refresh", "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		t.Fatalf("error making request to server. Err: %v", err)
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected status NotImplemented; got %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body. Err: %v", err)
	}
	expected := "Not Implemented\n"
	if string(body) != expected {
		t.Fatalf("expected response body %q; got %q", expected, string(body))
	}
}

func TestPostLogout_Unimplemented(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Post(server.URL+"/_matrix/client/v3/logout", "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		t.Fatalf("error making request to server. Err: %v", err)
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected status NotImplemented; got %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body. Err: %v", err)
	}
	expected := "Not Implemented\n"
	if string(body) != expected {
		t.Fatalf("expected response body %q; got %q", expected, string(body))
	}
}

func TestPostRegister_Unimplemented(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Post(server.URL+"/_matrix/client/v3/register", "application/json", bytes.NewBufferString("{}"))
	if err != nil {
		t.Fatalf("error making request to server. Err: %v", err)
	}
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected status NotImplemented; got %v", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body. Err: %v", err)
	}
	expected := "Not Implemented\n"
	if string(body) != expected {
		t.Fatalf("expected response body %q; got %q", expected, string(body))
	}
}
