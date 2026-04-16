package auth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/repository"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	userStore   repository.UserStore
	deviceStore repository.DeviceStore
}

func NewHandler(userStore repository.UserStore, deviceStore repository.DeviceStore) *Handler {
	return &Handler{userStore, deviceStore}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /_matrix/client/v3/login", h.getLogin)
	mux.HandleFunc("POST /_matrix/client/v3/login", h.postLogin)
	mux.HandleFunc("POST /_matrix/client/v3/refresh", h.postRefresh)
	mux.HandleFunc("POST /_matrix/client/v3/logout", h.postLogout)     // TODO: aplicar middleware de auth
	mux.HandleFunc("POST /_matrix/client/v3/register", h.postRegister) // TODO
}

// getLogin retorna os tipos de autenticação suportados pelo servidor, o cliente deve escolher um para usar em /login
func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: mais métodos de autenticação, tipo Captcha + Password ou OAuth
	response := LoginFlowsReponse{
		Flows: []Flow{{Type: types.AuthenticationTypePassword}},
	}
	util.WriteJSON(w, 200, response)
}

// postLogin autentica o usuário retornando um device_id e access_token
func (h *Handler) postLogin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), util.RequestTimeout)
	defer cancel()

	if r.Body == nil {
		util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_NOT_JSON, "Request body is empty"))
		return
	}

	var payload LoginRequest
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_BAD_JSON, err.Error()))
		return
	}

	if payload.Type != "m.login.password" {
		util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_UNRECOGNIZED, "Unsupported/Unknown auth type"))
		return
	}

	var user *model.Usuario
	if payload.Identifier.Type == types.IdentifierTypeUser {
		user, err = h.userStore.GetByLocal(ctx, payload.Identifier.User)
		if err != nil {
			log.Println("[ERROR] POST /login. Failed to query user.", err)
			util.WriteError(w, http.StatusForbidden, types.NewErrorResponse(types.M_FORBIDDEN, "Failed to authenticate to said user"))
		}
	} else {
		log.Printf("Unsupported/Unknown identifier type: %v", payload.Identifier.Type)
		util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_UNRECOGNIZED, "Unsupported/Unknown identifier type"))
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Senha), []byte(payload.Password)); err != nil {
		util.WriteError(w, http.StatusForbidden, types.NewErrorResponse(types.M_FORBIDDEN, "Failed to authenticate to said user."))
	}

	// Cria o token de refresh
	refreshToken, refreshExpires, err := GenerateRefreshToken()
	if err != nil {
		log.Printf("Failed to generate refresh token: %v", err)
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Failed to generate refresh token"))
		return
	}

	// Cria ou atualiza o disposivo atual
	deviceID := payload.DeviceID
	if deviceID == "" {
		newID, err := uuid.NewV7()
		if err != nil {
			log.Printf("Failed to generate device id: %v", err)
			util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Failed to generate device id"))
			return
		}
		deviceID = newID.String()
	}

	device := model.Dispositivo{
		ID:                    deviceID,
		Nome:                  payload.InitialDeviceDisplayName,
		UltimoIPVisto:         util.GetClientIP(r),
		UltimoTimestampVisto:  time.Now(),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpires,
	}

	err = h.deviceStore.CreateOrUpdate(ctx, &device)

	// cria os tokens de acesso
	accessToken, expiresMS, err := GenerateAccessToken(payload.Identifier.User, device.ID)
	if err != nil {
		log.Printf("Failed to generate access token: %v", err)
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Failed to generate access token"))
		return
	}

	if err != nil {
		log.Printf("Failed to create or update device: %v", err)
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Failed to create or update device"))
		return
	}

	response := LoginReponse{
		AccessToken:  accessToken,
		DeviceID:     device.ID,
		UserID:       user.ID,
		RefreshToken: device.RefreshToken,
		ExpireMS:     &expiresMS,
	}
	util.WriteJSON(w, 200, response)
}

// postRefresh "refresca" o access token do usuário.
func (h *Handler) postRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), util.RequestTimeout)
	defer cancel()

	var payload RefreshRequest
	if err := util.ParseBody(r, &payload); err != nil {
		var emsg types.ErrorResponse
		if err == types.ErrBodyRequired {
			emsg.ErrCode = types.M_NOT_JSON
			emsg.Message = "No request body"
		} else {
			emsg.ErrCode = types.M_BAD_JSON
			emsg.Message = "Invalid request body"
		}
		util.WriteError(w, http.StatusBadRequest, emsg)
		return
	}

	device, err := h.deviceStore.GetByRefreshToken(ctx, payload.RefreshToken)
	if err != nil {
		log.Printf("Failed to get device by refresh token: %v", err)
		util.WriteError(w, http.StatusUnauthorized, types.NewErrorResponse(types.M_UNAUTHORIZED, "Invalid refresh token"))
		return
	}

	// If refresh token is expired, negates refresh
	if device.RefreshTokenExpiresAt.Before(time.Now()) {
		util.WriteError(w, http.StatusUnauthorized, types.NewErrorResponse(types.M_UNAUTHORIZED, "Refresh token expired"))
		return
	}

	// creates new access token
	accessToken, expiresMS, err := GenerateAccessToken(device.UsuarioID, device.ID)
	if err != nil {
		log.Printf("Failed to generate access token: %v", err)
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Failed to generate access token"))
		return
	}

	response := RefreshResponse{
		AccessToken: accessToken,
		ExpireMS:    &expiresMS,
	}
	util.WriteJSON(w, 200, response)
}

// postLogout realiza o logout, invalidando o refresh token.
func (h *Handler) postLogout(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	deviceID := ctx.Value("device_id") // NOTE: considera que o middleware de autenticação injetou esses valores a partir do access token

	device, err := h.deviceStore.GetByID(ctx, deviceID)
	if err != nil {
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Operation over device failed."))
		return
	}

	// invalida o token
	device.RefreshTokenExpiresAt = time.Now()
	if err := h.deviceStore.Update(ctx, device); err != nil {
		log.Printf("Failed to update device: %v", err)
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Operation over device failed."))
		return
	}

	util.WriteJSON(w, 200, map[string]any{})
}

// postRegister realiza o registro de novos usuários
func (h *Handler) postRegister(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var req RegisterRequest
	if err := util.ParseBody(r, &req); err != nil {
		util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_BAD_JSON, "Invalid request body"))
		return
	}

	props := model.UsuarioCreate{}
	user, err := props.ToUsuario()
	if err != nil {
		if err == types.ErrInvalidUsername {
			util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_INVALID_USERNAME, "Invalid username"))
		} else {
			log.Printf("failed to parse user: %v", err)
			util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Parsing failed."))
		}
		return
	}
	// Cria novo usuario
	err = h.userStore.Create(ctx, &user)
	if err != nil {
		// Falha se o nome já existir
		if err == types.ErrLocalpartInUse {
			util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_USER_IN_USE, "Username already exists"))
		} else {
			log.Printf("failed to create user: %v", err)
			util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Operation failed."))
		}
		return
	}

	response := RegisterResponse{
		UserID: user.ID,
	}
	// Se cadastro loga o usuario
	if !req.InhibitLogin {
		refreshToken, refreshExpires, err := GenerateRefreshToken()
		if err != nil {
			log.Printf("Failed to generate refresh token: %v", err)
			util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Failed to generate refresh token"))
			return
		}

		// create new Dispositivo
		device := model.Dispositivo{
			ID:                    req.DeviceID,
			Nome:                  req.InitialDeviceDisplayName,
			UltimoIPVisto:         util.GetClientIP(r),
			UltimoTimestampVisto:  time.Now(),
			RefreshToken:          refreshToken,
			RefreshTokenExpiresAt: refreshExpires,
		}

		// criar novo access_token
		accessToken, expiresMS, err := GenerateAccessToken(user.LocalPart, device.ID)
		if err != nil {
			log.Printf("Failed to generate access token: %v", err)
			util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Failed to generate access token"))
			return
		}

		// Inclui autenticacao
		response = RegisterResponse{
			UserID:       response.UserID,
			DeviceID:     device.ID,
			AccessToken:  accessToken,
			ExpireMS:     &expiresMS,
			RefreshToken: refreshToken,
		}
	}
	util.WriteJSON(w, http.StatusOK, response)
}
