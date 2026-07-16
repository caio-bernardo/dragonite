package presence

import (
	"errors"
	"net/http"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

// Handler agrupa as rotas de presence do cliente Matrix
type Handler struct {
	presenceService *usecase.PresenceService
}

func NewHandler(presenceService *usecase.PresenceService) *Handler {
	return &Handler{presenceService: presenceService}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware httputil.Middleware) {
	mux.Handle("GET /_matrix/client/v3/presence/{userId}/status", authMiddleware(http.HandlerFunc(h.getPresenceStatus)))
	// TODO: adicionar rate limiting antes do authMiddleware quando a infraestrutura
	// de rate limiting for implementada no projeto.
	mux.Handle("PUT /_matrix/client/v3/presence/{userId}/status", authMiddleware(http.HandlerFunc(h.putPresenceStatus)))
}

// getPresenceStatus retorna o estado de presença de um usuário
// GET /_matrix/client/v3/presence/{userId}/status
func (h *Handler) getPresenceStatus(w http.ResponseWriter, r *http.Request) {
	requesterID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || requesterID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}
	targetUserID := r.PathValue("userId")

	presence, err := h.presenceService.GetStatus(r.Context(), requesterID, targetUserID)
	if err != nil {
		switch {
		case errors.Is(err, types.ErrForbidden):
			httputil.WriteMatrixError(w, http.StatusForbidden, httputil.M_FORBIDDEN, "You are not allowed to see their presence")
		case errors.Is(err, types.ErrNotFound):
			// A spec usa M_UNKNOWN (não M_NOT_FOUND) no exemplo de 404 deste endpoint
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_UNKNOWN, "There is no presence state for this user")
		default:
			httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to fetch presence")
		}
		return
	}

	httputil.WriteJSON(w, http.StatusOK, PresenceStatusResponse{
		CurrentlyActive: false, // TODO: calcular atividade real com base num threshold de last_active_at
		LastActiveAgo:   time.Since(presence.LastActiveAt).Milliseconds(),
		Presence:        string(presence.State),
		StatusMsg:       presence.StatusMsg,
	})
}

// putPresenceStatus atualiza o estado de presença do próprio usuário autenticado
// PUT /_matrix/client/v3/presence/{userId}/status
func (h *Handler) putPresenceStatus(w http.ResponseWriter, r *http.Request) {
	requesterID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || requesterID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}
	targetUserID := r.PathValue("userId")

	// A spec proíbe explicitamente setar a presença de outro usuário
	if requesterID != targetUserID {
		httputil.WriteMatrixError(w, http.StatusForbidden, httputil.M_FORBIDDEN, "You cannot set the presence state of another user")
		return
	}

	var req PresenceStatusRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		if err == types.ErrNoBodyFound {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "No request body")
		} else {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Invalid request body")
		}
		return
	}

	if req.Presence == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "presence is required")
		return
	}

	err := h.presenceService.SetStatus(r.Context(), requesterID, domain.PresenceState(req.Presence), req.StatusMsg)
	if err != nil {
		if errors.Is(err, types.ErrInvalidParam) {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "Invalid presence state")
			return
		}
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to update presence")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}