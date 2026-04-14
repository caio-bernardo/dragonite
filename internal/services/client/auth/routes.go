package auth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/repository"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	userStore repository.UserStore
}

func NewHandler(userStore repository.UserStore) *Handler {
	return &Handler{userStore}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /_matrix/client/v3/login", h.getLogin)                    // TODO
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
	_, cancel := context.WithTimeout(context.Background(), util.RequestTimeout)
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
		// TODO: needs new method
		// user, err = h.userStore.GetByLocalPart(payload.Identifier.User)
		if err != nil {
			log.Println("[ERROR] POST /login. Failed to query user.", err)
			util.WriteError(w, http.StatusForbidden, types.NewErrorResponse(types.M_FORBIDDEN, "Failed to authenticate to said user"))
		}
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Senha), []byte(payload.Password)); err != nil {
		util.WriteError(w, http.StatusForbidden, types.NewErrorResponse(types.M_FORBIDDEN, "Failed to authenticate to said user."))
	}

	// TODO: criar novo access token

	response := LoginReponse{
		AccessToken: "abc123",
		DeviceID:    "123",
		UserID:      user.GetMatrixUserID(),
	}
	util.WriteJSON(w, 200, response)
}
