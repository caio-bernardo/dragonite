package profile

import (
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

type Handler struct {
	profileService *usecase.ProfileService
}

func NewHandler(profileService *usecase.ProfileService) *Handler {
	return &Handler{profileService: profileService}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware httputil.Middleware) {

	// Chave do perfil do usuário
	mux.HandleFunc("GET /_matrix/client/v3/profile/{userId}/keys", h.getProfileKey)

	// Alterar chave do perfil do usuário
	mux.Handle("PUT /_matrix/client/v3/profile/{userId}/keys", authMiddleware(http.HandlerFunc(h.putProfileKey)))

	// Remover chave do perfil do usuário
	mux.Handle("DELETE /_matrix/client/v3/profile/{userId}/keys", authMiddleware(http.HandlerFunc(h.deleteProfileKey)))

}

// GET /_matrix/client/v3/profile/{userId}
func (h *Handler) getProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")

	profile, err := h.profileService.GetProfileByUserID(r.Context(), userID)

	if err != nil {
		if err == types.ErrNotFound {
			httputil.WriteMatrixError(w, http.StatusNotFound,
				"M_NOT_FOUND",
				"Profile not found",
			)
			return
		}
		httputil.WriteMatrixError(w, http.StatusInternalServerError,
			"M_UNKNOWN",
			"Internal server error",
		)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, profile)
}

// GET /_matrix/client/v3/profile/{userId}/{keyName}
func (h *Handler) getProfileKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	keyName := r.PathValue("keyName") // Vai ser "displayname" ou "avatar_url"

	usuario, err := h.profileService.GetProfileByUserID(r.Context(), userID)

	if err != nil {
		if err == types.ErrNotFound {
			httputil.WriteMatrixError(w, http.StatusNotFound,
				"M_NOT_FOUND",
				"User not found",
			)
			return
		}
		httputil.WriteMatrixError(w, http.StatusInternalServerError,
			"M_UNKNOWN",
			"Internal server error",
		)
		return
	}

	var valor *string
	if keyName == "displayname" {
		valor = usuario.DisplayName
	} else if keyName == "avatar_url" {
		valor = usuario.AvatarURL
	} else {
		// Se pediu uma chave que não existe no Matrix
		httputil.WriteMatrixError(w, http.StatusBadRequest,
			"M_BAD_JSON",
			"Invalid profile key",
		)
		return
	}

	response := map[string]*string{
		keyName: valor,
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// PUT /_matrix/client/v3/profile/{userId}/{keyName}
func (h *Handler) putProfileKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	keyName := r.PathValue("keyName") // "displayname" ou "avatar_url"

	var reqBody map[string]string
	if err := httputil.ParseBody(r, &reqBody); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest,
			"M_NOT_JSON",
			"Request body must be JSON",
		)
		return
	}

	novoValor, existe := reqBody[keyName]
	if !existe {
		httputil.WriteMatrixError(w, http.StatusBadRequest,
			"M_BAD_JSON",
			"Missing key in request body",
		)
		return
	}

	props := usecase.ProfileParams{
		DisplayName: nil,
		AvatarURL:   nil,
	}

	switch keyName {
	case "displayname":
		props.DisplayName = &novoValor
	case "avatar_url":
		props.AvatarURL = &novoValor
	}

	err := h.profileService.UpdateProfile(r.Context(), userID, props)
	if err != nil {
		if err == types.ErrNotFound {
			httputil.WriteMatrixError(w, http.StatusNotFound,
				"M_NOT_FOUND",
				"User not found",
			)
			return
		}

		httputil.WriteMatrixError(w, http.StatusInternalServerError,
			"M_UNKNOWN",
			"Database error",
		)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{})
}

// DELETE /_matrix/client/v3/profile/{userId}/{keyName}
func (h *Handler) deleteProfileKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	keyName := r.PathValue("keyName")

	props := usecase.ProfileParams{
		DisplayName: nil,
		AvatarURL:   nil,
	}

	switch keyName {
	case "displayname":
		props.DisplayName = new("")
	case "avatar_url":
		props.AvatarURL = new("")
	}

	err := h.profileService.UpdateProfile(r.Context(), userID, props)

	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError,
			"M_UNKNOWN",
			"Database error",
		)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{})
}
