package account

import (
	"encoding/json"
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

type Handler struct {
	accountService *usecase.AccountService
}

func NewHandler(accountService *usecase.AccountService) *Handler {
	return &Handler{accountService: accountService}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware httputil.Middleware) {
	// account
	mux.Handle("GET /_matrix/client/v3/account/whoami", authMiddleware(http.HandlerFunc(h.whoami)))

	// user-scoped
	mux.Handle("PUT /_matrix/client/v3/user/{userId}/account_data/{type}", authMiddleware(http.HandlerFunc(h.putUserAccountData)))
	mux.HandleFunc("GET /_matrix/client/v3/user/{userId}/account_data/{type}", h.getUserAccountData)

	// room-scoped
	mux.Handle("PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}", authMiddleware(http.HandlerFunc(h.putRoomAccountData)))
	mux.HandleFunc("GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}", h.getRoomAccountData)
}

// GET /_matrix/client/v3/account/whoami
// Retorna o user_id e device_id associados ao access_token usado na requisição
// NOTE: não trata masquerading de Application Services (?user_id=)
func (h *Handler) whoami(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_UNKNOWN_TOKEN, "Unrecognised access token.")
		return
	}

	deviceID, _ := r.Context().Value(types.DeviceIDKey).(string)

	response := WhoamiResponse{
		UserID:   userID,
		DeviceID: deviceID, // fica de fora do JSON automaticamente se vazio (omitempty)
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// PUT /_matrix/client/v3/user/{userId}/account_data/{type}
func (h *Handler) putUserAccountData(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	tipo := r.PathValue("type")
	// ponytail: fallback naive parse when path params not provided (tests call handlers directly)
	if userID == "" || tipo == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "Missing path parameters")
		return
	}

	var raw json.RawMessage
	if err := httputil.ParseBody(r, &raw); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Request body must be JSON")
		return
	}

	if h.accountService == nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Service not available")
		return
	}

	err := h.accountService.PutUserAccountData(r.Context(), userID, "", tipo, raw)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to save account data")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{})
}

// GET /_matrix/client/v3/user/{userId}/account_data/{type}
func (h *Handler) getUserAccountData(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	tipo := r.PathValue("type")
	if userID == "" || tipo == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "Missing path parameters")
		return
	}

	if h.accountService == nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Service not available")
		return
	}

	acct, err := h.accountService.GetUserAccountData(r.Context(), userID, "", tipo)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to get account data")
		return
	}
	if acct == nil {
		httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Account data not found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, acct)
}

// PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
func (h *Handler) putRoomAccountData(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	roomID := r.PathValue("roomId")
	tipo := r.PathValue("type")
	if userID == "" || roomID == "" || tipo == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "Missing path parameters")
		return
	}

	var raw json.RawMessage
	if err := httputil.ParseBody(r, &raw); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Request body must be JSON")
		return
	}

	if h.accountService == nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Service not available")
		return
	}

	err := h.accountService.PutUserAccountData(r.Context(), userID, roomID, tipo, raw)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to save account data")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{})
}

// GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
func (h *Handler) getRoomAccountData(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	roomID := r.PathValue("roomId")
	tipo := r.PathValue("type")
	if userID == "" || roomID == "" || tipo == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "Missing path parameters")
		return
	}

	if h.accountService == nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Service not available")
		return
	}

	acct, err := h.accountService.GetUserAccountData(r.Context(), userID, roomID, tipo)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to get account data")
		return
	}
	if acct == nil {
		httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Account data not found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, acct)
}
