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
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// MockUserStore is a mock implementation of repository.UserStore for testing
type MockUserStore struct {
	userByLocal    *model.Usuario
	userByLocalErr error
	createCalled   bool
	createUser     *model.Usuario
	createErr      error
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
	m.createCalled = true
	m.createUser = usuario
	return m.createErr
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

	getByRefreshTokenDevice *model.Dispositivo
	getByRefreshTokenErr    error

	getByIDDevice *model.Dispositivo
	getByIDErr    error

	updateCalled bool
	updateDevice *model.Dispositivo
	updateErr    error
}

// GetByRefreshToken implements [repository.DeviceStore].
func (m *MockDeviceStore) GetByRefreshToken(ctx context.Context, refreshToken string) (*model.Dispositivo, error) {
	return m.getByRefreshTokenDevice, m.getByRefreshTokenErr
}

func (m *MockDeviceStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Dispositivo, error) {
	return []model.Dispositivo{}, nil
}

func (m *MockDeviceStore) GetByID(ctx context.Context, id string) (*model.Dispositivo, error) {
	return m.getByIDDevice, m.getByIDErr
}

func (m *MockDeviceStore) Create(ctx context.Context, props *model.Dispositivo) error {
	return nil
}

func (m *MockDeviceStore) Update(ctx context.Context, props *model.Dispositivo) error {
	m.updateCalled = true
	m.updateDevice = props
	return m.updateErr
}

func (m *MockDeviceStore) CreateOrUpdate(ctx context.Context, props *model.Dispositivo) error {
	m.createOrUpdateCalled = true
	m.createOrUpdateDevice = props
	return m.createOrUpdateErr
}

func (m *MockDeviceStore) Delete(ctx context.Context, id string) (*model.Dispositivo, error) {
	return nil, nil
}

// Helper function to create a valid JWT token for testing
func createTestToken(userID, deviceID string) (string, error) {
	originalKey := types.JWTSecretKey
	defer func() { types.JWTSecretKey = originalKey }()

	types.JWTSecretKey = []byte("test-secret-key")

	claims := types.MatrixClaims{
		UserID:   userID,
		DeviceID: deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(types.JWTSecretKey)
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
	originalKey := types.JWTSecretKey
	types.JWTSecretKey = []byte("test-secret")
	defer func() {
		types.JWTSecretKey = originalKey
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

func TestPostRefresh_BadJSON(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/refresh", bytes.NewBufferString("{bad-json"))
	rr := httptest.NewRecorder()

	h.postRefresh(rr, req)

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

func TestPostRefresh_InvalidToken(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{
		getByRefreshTokenErr: types.ErrNotFound,
	}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	payload := RefreshRequest{RefreshToken: "bad-token"}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/refresh", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	h.postRefresh(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status Unauthorized; got %v", rr.Code)
	}

	var response types.ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.ErrCode != types.M_UNAUTHORIZED {
		t.Fatalf("expected errcode %q; got %q", types.M_UNAUTHORIZED, response.ErrCode)
	}
}

func TestPostRefresh_ExpiredToken(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{
		getByRefreshTokenDevice: &model.Dispositivo{
			ID:                    "DEVICE",
			UsuarioID:             "@user:example.com",
			RefreshToken:          "expired",
			RefreshTokenExpiresAt: time.Now().Add(-time.Minute),
		},
	}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	payload := RefreshRequest{RefreshToken: "expired"}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/refresh", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	h.postRefresh(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status Unauthorized; got %v", rr.Code)
	}

	var response types.ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.ErrCode != types.M_UNAUTHORIZED {
		t.Fatalf("expected errcode %q; got %q", types.M_UNAUTHORIZED, response.ErrCode)
	}
}

func TestPostRefresh_Success(t *testing.T) {
	originalKey := types.JWTSecretKey
	types.JWTSecretKey = []byte("test-secret")
	defer func() {
		types.JWTSecretKey = originalKey
	}()

	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{
		getByRefreshTokenDevice: &model.Dispositivo{
			ID:                    "DEVICE",
			UsuarioID:             "@user:example.com",
			RefreshToken:          "valid",
			RefreshTokenExpiresAt: time.Now().Add(time.Hour),
		},
	}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	payload := RefreshRequest{RefreshToken: "valid"}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/refresh", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	h.postRefresh(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status OK; got %v", rr.Code)
	}

	var response RefreshResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.AccessToken == "" {
		t.Fatalf("expected access_token to be set")
	}
	if response.ExpireMS == nil || *response.ExpireMS <= 0 {
		t.Fatalf("expected expire_ms to be set with positive value")
	}
}

func TestPostLogout_Success(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{
		getByIDDevice: &model.Dispositivo{
			ID:                    "DEVICE",
			UsuarioID:             "@user:example.com",
			RefreshToken:          "refresh",
			RefreshTokenExpiresAt: time.Now().Add(time.Hour),
		},
	}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/logout", bytes.NewBufferString("{}"))
	req = req.WithContext(context.WithValue(req.Context(), types.DeviceIDKey, "DEVICE"))
	rr := httptest.NewRecorder()

	h.postLogout(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status OK; got %v", rr.Code)
	}

	if rr.Body.String() != "{}" {
		t.Fatalf("expected empty JSON object response; got %q", rr.Body.String())
	}

	if !mockDeviceStore.updateCalled {
		t.Fatalf("expected device store update to be called")
	}
	if mockDeviceStore.updateDevice == nil {
		t.Fatalf("expected update device to be set")
	}
	if mockDeviceStore.updateDevice.RefreshTokenExpiresAt.IsZero() {
		t.Fatalf("expected refresh token expiration to be set")
	}
	if time.Since(mockDeviceStore.updateDevice.RefreshTokenExpiresAt) > 2*time.Second {
		t.Fatalf("expected refresh token expiration to be recent")
	}
}

func TestPostLogout_DeviceLookupError(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{
		getByIDErr: types.ErrNotFound,
	}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/logout", bytes.NewBufferString("{}"))
	req = req.WithContext(context.WithValue(req.Context(), types.DeviceIDKey, "DEVICE"))
	rr := httptest.NewRecorder()

	h.postLogout(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status InternalServerError; got %v", rr.Code)
	}

	var response types.ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.ErrCode != types.M_UNKNOWN {
		t.Fatalf("expected errcode %q; got %q", types.M_UNKNOWN, response.ErrCode)
	}
}

func TestPostRegister_BadJSON(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/register", bytes.NewBufferString("{bad-json"))
	rr := httptest.NewRecorder()

	h.postRegister(rr, req)

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

func TestPostRegister_InvalidUsername(t *testing.T) {
	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	payload := RegisterRequest{
		Username: "user:bad",
		Password: "password",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/register", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	h.postRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status BadRequest; got %v", rr.Code)
	}

	var response types.ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.ErrCode != types.M_INVALID_USERNAME {
		t.Fatalf("expected errcode %q; got %q", types.M_INVALID_USERNAME, response.ErrCode)
	}
}

func TestPostRegister_Success_InhibitLogin(t *testing.T) {
	originalServerName := util.ServerName
	util.ServerName = "example.com"
	defer func() {
		util.ServerName = originalServerName
	}()

	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	payload := RegisterRequest{
		Username:                 "user",
		Password:                 "password",
		InhibitLogin:             true,
		RefreshToken:             false,
		DeviceID:                 "DEVICE",
		InitialDeviceDisplayName: "My Phone",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/register", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	h.postRegister(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status OK; got %v", rr.Code)
	}

	var response RegisterResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.UserID != "@user:example.com" {
		t.Fatalf("expected user_id %q; got %q", "@user:example.com", response.UserID)
	}
	if response.AccessToken != "" || response.RefreshToken != "" || response.DeviceID != "" || response.ExpireMS != nil {
		t.Fatalf("expected no login data when inhibit_login is true")
	}

	if !mockUserStore.createCalled {
		t.Fatalf("expected user store create to be called")
	}
	if mockUserStore.createUser == nil {
		t.Fatalf("expected created user to be captured")
	}
	if mockUserStore.createUser.LocalPart != "user" {
		t.Fatalf("expected localpart %q; got %q", "user", mockUserStore.createUser.LocalPart)
	}
	if mockUserStore.createUser.ID != response.UserID {
		t.Fatalf("expected created user ID to match response")
	}
	if mockUserStore.createUser.Senha == "password" {
		t.Fatalf("expected stored password to be hashed")
	}
}

func TestPostRegister_Success_WithLogin(t *testing.T) {
	originalKey := types.JWTSecretKey
	types.JWTSecretKey = []byte("test-secret")
	defer func() {
		types.JWTSecretKey = originalKey
	}()

	originalServerName := util.ServerName
	util.ServerName = "example.com"
	defer func() {
		util.ServerName = originalServerName
	}()

	mockUserStore := MockUserStore{}
	mockDeviceStore := MockDeviceStore{}
	h := NewHandler(&mockUserStore, &mockDeviceStore)

	payload := RegisterRequest{
		Username:                 "user",
		Password:                 "password",
		DeviceID:                 "DEVICE",
		InitialDeviceDisplayName: "My Phone",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/_matrix/client/v3/register", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	h.postRegister(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status OK; got %v", rr.Code)
	}

	var response RegisterResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if response.UserID != "@user:example.com" {
		t.Fatalf("expected user_id %q; got %q", "@user:example.com", response.UserID)
	}
	if response.DeviceID != payload.DeviceID {
		t.Fatalf("expected device_id %q; got %q", payload.DeviceID, response.DeviceID)
	}
	if response.AccessToken == "" {
		t.Fatalf("expected access_token to be set")
	}
	if response.RefreshToken == "" {
		t.Fatalf("expected refresh_token to be set")
	}
	if response.ExpireMS == nil || *response.ExpireMS <= 0 {
		t.Fatalf("expected expire_ms to be set with positive value")
	}
}
