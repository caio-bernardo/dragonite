package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

type Handler struct {
	authService *usecase.AuthService
}

func NewHandler(authService *usecase.AuthService) *Handler {
	return &Handler{authService: authService}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware httputil.Middleware) {
	mux.HandleFunc("GET /_matrix/client/v3/login", h.getLogin)
	mux.HandleFunc("POST /_matrix/client/v3/login", h.postLogin)
	mux.HandleFunc("POST /_matrix/client/v3/refresh", h.postRefresh)
	mux.Handle("POST /_matrix/client/v3/logout", authMiddleware(http.HandlerFunc(h.postLogout)))
	mux.HandleFunc("POST /_matrix/client/v3/register", h.postRegister)
	mux.HandleFunc("GET /_matrix/client/v3/register/available", h.getAvailable)
}

func (h *Handler) getAvailable(w http.ResponseWriter, r *http.Request) {

	username := r.URL.Query().Get("username")
	if username == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_USERNAME, "empty username")
		return
	}

	// TODO: implementar isso
	// available, err := h.authService.IsUsernameAvailable(username)
	// if err != nil {
	// 	httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, err.Error())
	// 	return
	// }

	resp := map[string]bool{
		"available": true,
	}
	httputil.WriteJSON(w, 200, resp)
}

// getLogin retorna os tipos de autenticação suportados pelo servidor, o cliente deve escolher um para usar em /login
func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: mais métodos de autenticação, tipo Captcha + Password ou OAuth
	response := LoginFlowsReponse{
		Flows: []Flow{{Type: types.AuthenticationTypePassword}},
	}
	httputil.WriteJSON(w, 200, response)
}

// postLogin autentica o usuário retornando um device_id e access_token
func (h *Handler) postLogin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), httputil.RequestTimeout)
	defer cancel()

	var payload LoginRequest
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, err.Error())
		return
	}

	if payload.Type != "m.login.password" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_UNRECOGNIZED, "Unsupported/Unknown auth type")
		return
	}

	// if payload.Identifier.Type == "" {
	// 	httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing user identifier")
	// 	return
	// }

	success, err := h.authService.Login(ctx, usecase.LoginParams{
		Indentifier: payload.Identifier,
		Password:    payload.Password,
		DeviceID:    payload.DeviceID,
		DeviceName:  payload.InitialDeviceDisplayName,
		DeviceIP:    httputil.GetClientIP(r),
	})

	if err != nil {
		if errors.Is(err, types.ErrUnimplemented) {
			httputil.WriteMatrixError(w, http.StatusNotImplemented, httputil.M_UNKNOWN, "this indentification method is unsupported right now")
		} else if errors.Is(err, types.ErrInvalidCredentials) {
			httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_FORBIDDEN, "invalid credentials")
		} else {
			httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, err.Error())
		}
		return
	}

	response := LoginReponse{
		AccessToken:  success.AccessToken,
		DeviceID:     success.DeviceID,
		UserID:       success.UserID,
		RefreshToken: success.RefreshToken,
		ExpireMS:     success.ExpireMS,
	}
	httputil.WriteJSON(w, 200, response)
}

// postRefresh "refresca" o access token do usuário.
func (h *Handler) postRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	var payload RefreshRequest
	if err := httputil.ParseBody(r, &payload); err != nil {
		var emsg httputil.MatrixErrorResponse
		if err == types.ErrNoBodyFound {
			emsg.ErrCode = httputil.M_NOT_JSON
			emsg.Message = "No request body"
		} else {
			emsg.ErrCode = httputil.M_BAD_JSON
			emsg.Message = "Invalid request body"
		}
		httputil.WriteError(w, http.StatusBadRequest, emsg)
		return
	}

	accessToken, expiresMS, err := h.authService.Refresh(ctx, payload.RefreshToken)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_UNAUTHORIZED, "Refresh token is invalid")
		return
	}

	response := RefreshResponse{
		AccessToken: accessToken,
		ExpireMS:    &expiresMS,
	}
	httputil.WriteJSON(w, 200, response)
}

// postLogout realiza o logout, invalidando o refresh token.
func (h *Handler) postLogout(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	userID := ctx.Value(types.UserIDKey).(string)
	deviceID := ctx.Value(types.DeviceIDKey).(string) // NOTE: considera que o middleware de autenticação injetou esses valores a partir do access token
	if deviceID == "" {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Missing device_id in context.")
		return
	}

	err := h.authService.Logout(ctx, userID, deviceID)
	if err != nil {
		log.Printf("Failed to logout: %v", err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to logout")
		return
	}

	httputil.WriteJSON(w, 200, map[string]any{})
}

// postRegister realiza o registro de novos usuários
func (h *Handler) postRegister(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var req RegisterRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Invalid request body")
		return
	}

	if req.Auth.Type == "" && req.Auth.Session == "" {
		resp := map[string]any{
			"flows": []any{
				map[string]any{"stages": []any{"m.login.password"}},
			},
			"params":  map[string]any{},
			"session": "1234",
		}
		httputil.WriteJSON(w, http.StatusUnauthorized, resp)
		return
	}

	userID, err := h.authService.Register(ctx, usecase.RegisterParams{
		Username: req.Username,
		Senha:    req.Password,
	})
	if err != nil {
		if err == types.ErrAlreadyInUse {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_USER_IN_USE, "Username already exists")
		} else {
			httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, err.Error())
		}
		return
	}

	response := RegisterResponse{
		UserID: userID,
	}
	// Se devemos logar o usuario
	if !req.InhibitLogin {
		success, err := h.authService.Login(ctx, usecase.LoginParams{
			Indentifier: types.UserIndentifier{
				Type: types.IdentifierTypeUser,
				User: userID,
			},
			Password: req.Password,
		})

		if err != nil {
			if errors.Is(err, types.ErrUnimplemented) {
				httputil.WriteMatrixError(w, http.StatusNotImplemented, httputil.M_UNKNOWN, "this indentification method is unsupported right now")
			} else if errors.Is(err, types.ErrInvalidCredentials) {
				httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_FORBIDDEN, "invalid credentials")
			} else {
				httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, err.Error())
			}
			return
		}

		response = RegisterResponse{
			AccessToken:  success.AccessToken,
			DeviceID:     success.DeviceID,
			UserID:       success.UserID,
			RefreshToken: success.RefreshToken,
			ExpireMS:     success.ExpireMS,
		}
	}
	httputil.WriteJSON(w, http.StatusOK, response)
}
