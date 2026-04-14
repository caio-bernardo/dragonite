package auth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/utils"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /_matrix/client/v3/login", h.getLogin)                     // TODO
	mux.HandleFunc("POST /_matrix/client/v3/login", h.postLogin)                   // TODO
	mux.HandleFunc("POST /_matrix/client/v3/refresh", utils.UnimplementedHandler)  // TODO
	mux.HandleFunc("POST /_matrix/client/v3/logout", utils.UnimplementedHandler)   // TODO
	mux.HandleFunc("POST /_matrix/client/v3/register", utils.UnimplementedHandler) // TODO
}

// getLogin retorna os tipos de autenticação suportados pelo servidor, o cliente deve escolher um para usar em /login
func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: mais métodos de autenticação, tipo Captcha + Password ou OAuth
	response := LoginFlowsReponse{
		Flows: []Flow{{Type: types.AuthenticationTypePassword}},
	}
	utils.WriteJSON(w, 200, response)
}

// postLogin autentica o usuário retornando um device_id e access_token
func (h *Handler) postLogin(w http.ResponseWriter, r *http.Request) {
	_, cancel := context.WithTimeout(context.Background(), utils.RequestTimeout)
	defer cancel()

	if r.Body == nil {
		utils.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_NOT_JSON, "Request body is empty"))
		return
	}

	var payload LoginRequest
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_BAD_JSON, err.Error()))
		return
	}

	if payload.Type != "m.login.password" {
		utils.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_UNRECOGNIZED, "Unsupported/Unknown auth type"))
		return
	}

	// TODO: needs database
	// var user *User
	// if payload.Identifier.Type == types.IdentifierTypeUser {
	// 	user, err = h.store.fetchUser(payload.Identifier.User)
	// 	if err != nil {
	// 		log.Println("[ERROR] POST /login. Failed to query user.", err)
	// 		utils.WriteError(w, http.StatusForbidden, types.NewErrorResponse(types.M_FORBIDDEN, "Failed to authenticate to said user"))
	// 	}
	// }
	// if err := bcrypt.CompareHashAndPassword(user.hashedPassword, []byte(payload.Password)); err != nil {
	// 	utils.WriteError(w, http.StatusForbidden, types.NewErrorResponse(types.M_FORBIDDEN, "Failed to authenticate to said user."))
	// }

	// TODO: criar access_token
	// TODO: criar new device id if not exists

	response := LoginReponse{
		AccessToken: "abc123",
		DeviceID:    "123",
		UserID:      "abc",
	}
	utils.WriteJSON(w, 200, response)
}
