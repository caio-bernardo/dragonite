package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/repository"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
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
	mux.HandleFunc("POST /_matrix/client/v3/login", h.postLogin)                  // TODO
	mux.HandleFunc("POST /_matrix/client/v3/refresh", util.UnimplementedHandler)  // TODO
	mux.HandleFunc("POST /_matrix/client/v3/logout", util.UnimplementedHandler)   // TODO
	mux.HandleFunc("POST /_matrix/client/v3/register", util.UnimplementedHandler) // TODO
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

	// cria os tokens de acesso e de refresh
	accessToken, expiresMS, err := GenerateAccessToken(payload.Identifier.User, payload.DeviceID)
	if err != nil {
		log.Printf("Failed to generate access token: %v", err)
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Failed to generate access token"))
		return
	}

	refreshToken, refreshExpires, err := GenerateRefreshToken()
	if err != nil {
		log.Printf("Failed to generate refresh token: %v", err)
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Failed to generate refresh token"))
		return
	}

	// Cria ou atualiza o disposivo atual
	device := model.Dispositivo{
		ID:                    payload.DeviceID,
		Nome:                  payload.InitialDeviceDisplayName,
		UltimoIPVisto:         util.GetClientIP(r),
		UltimoTimestampVisto:  time.Now(),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpires,
	}

	err = h.deviceStore.CreateOrUpdate(ctx, &device)
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

func generateRandomCode(size int) string {
	bytes := make([]byte, size)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
