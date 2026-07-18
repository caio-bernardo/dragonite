package roomkeys

import (
	"log"
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

// uploadCrossSigningKeys publica as chaves de cross-signing (master/self_signing/user_signing) do usuário
// POST /_matrix/client/v3/keys/device_signing/upload
func (h *Handler) uploadCrossSigningKeys(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}

	var req UploadCrossSigningRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Request did not contain valid JSON")
		return
	}

	if len(req.MasterKey) == 0 && len(req.SelfSigningKey) == 0 && len(req.UserSigningKey) == 0 {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "No signing keys provided")
		return
	}

	err := h.keysService.UploadCrossSigningKeys(r.Context(), usecase.UploadCrossSigningKeysParams{
		UserID:         userID,
		MasterKey:      req.MasterKey,
		SelfSigningKey: req.SelfSigningKey,
		UserSigningKey: req.UserSigningKey,
	})
	if err != nil {
		log.Printf("[ERROR] POST /_matrix/client/v3/keys/device_signing/upload (user=%s): %v", userID, err)
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}

// uploadSignatures funde novas assinaturas nas chaves de dispositivo ou de cross-signing já armazenadas
// POST /_matrix/client/v3/keys/signatures/upload
func (h *Handler) uploadSignatures(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.Context().Value(types.UserIDKey).(string); !ok {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}

	var req UploadSignaturesRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Request did not contain valid JSON")
		return
	}

	result := h.keysService.UploadSignatures(r.Context(), req)

	httputil.WriteJSON(w, http.StatusOK, UploadSignaturesResponse{Failures: result.Failures})
}
