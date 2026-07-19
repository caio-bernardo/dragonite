package roomkeys

import (
	"log"
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

// uploadKeys publica as chaves de identidade, one-time keys e fallback keys do dispositivo autenticado
// POST /_matrix/client/v3/keys/upload
func (h *Handler) uploadKeys(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}
	deviceID, ok := r.Context().Value(types.DeviceIDKey).(string)
	if !ok || deviceID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing device_id in context")
		return
	}

	var req UploadKeysRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		if err == types.ErrNoBodyFound {
			// device_keys/one_time_keys/fallback_keys são todos opcionais; corpo vazio é válido
			req = UploadKeysRequest{}
		} else {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Request did not contain valid JSON")
			return
		}
	}

	params := usecase.UploadKeysParams{
		UserID:       userID,
		DeviceID:     deviceID,
		OneTimeKeys:  req.OneTimeKeys,
		FallbackKeys: req.FallbackKeys,
	}
	if req.DeviceKeys != nil {
		if req.DeviceKeys.UserID != "" && req.DeviceKeys.UserID != userID {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "device_keys.user_id does not match the authenticated user")
			return
		}
		if req.DeviceKeys.DeviceID != "" && req.DeviceKeys.DeviceID != deviceID {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "device_keys.device_id does not match the authenticated device")
			return
		}
		params.Algorithms = req.DeviceKeys.Algorithms
		params.IdentityKeys = req.DeviceKeys.Keys
		params.Signatures = req.DeviceKeys.Signatures
	}

	counts, err := h.keysService.UploadKeys(r.Context(), params)
	if err != nil {
		log.Printf("[ERROR] POST /_matrix/client/v3/keys/upload (user=%s device=%s): %v", userID, deviceID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to upload keys")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, UploadKeysResponse{OneTimeKeyCounts: counts})
}

// queryKeys retorna as chaves de identidade (e, se aplicável, de cross-signing) dos dispositivos
// pedidos (locais ou federados)
// POST /_matrix/client/v3/keys/query
func (h *Handler) queryKeys(w http.ResponseWriter, r *http.Request) {
	requestingUserID, _ := r.Context().Value(types.UserIDKey).(string)

	var req QueryKeysRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Request did not contain valid JSON")
		return
	}

	result := h.keysService.QueryKeys(r.Context(), requestingUserID, req.DeviceKeys)

	response := QueryKeysResponse{
		DeviceKeys:      make(map[string]map[string]DeviceKeysInfo),
		MasterKeys:      make(map[string]CrossSigningKeyInfo),
		SelfSigningKeys: make(map[string]CrossSigningKeyInfo),
		UserSigningKeys: make(map[string]CrossSigningKeyInfo),
		Failures:        result.Failures,
	}
	for userID, devices := range result.DeviceKeys {
		devMap := make(map[string]DeviceKeysInfo, len(devices))
		for deviceID, k := range devices {
			devMap[deviceID] = DeviceKeysInfo{
				Algorithms: k.Algorithms,
				DeviceID:   deviceID,
				Keys:       k.Keys,
				Signatures: k.Signatures,
				UserID:     userID,
				Unsigned:   UnsignedDevice{DeviceDisplayName: k.NomeDispositivo},
			}
		}
		response.DeviceKeys[userID] = devMap
	}
	for userID, k := range result.MasterKeys {
		response.MasterKeys[userID] = toCrossSigningKeyInfo(userID, k)
	}
	for userID, k := range result.SelfSigningKeys {
		response.SelfSigningKeys[userID] = toCrossSigningKeyInfo(userID, k)
	}
	for userID, k := range result.UserSigningKeys {
		response.UserSigningKeys[userID] = toCrossSigningKeyInfo(userID, k)
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

func toCrossSigningKeyInfo(userID string, k domain.ChaveCrossSigning) CrossSigningKeyInfo {
	return CrossSigningKeyInfo{
		Keys:       k.Keys,
		Signatures: k.Signatures,
		Usage:      []string{k.Usage},
		UserID:     userID,
	}
}

// claimKeys reivindica one-time keys dos dispositivos pedidos (locais ou federados)
// POST /_matrix/client/v3/keys/claim
func (h *Handler) claimKeys(w http.ResponseWriter, r *http.Request) {
	var req ClaimKeysRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Request did not contain valid JSON")
		return
	}

	result := h.keysService.ClaimKeys(r.Context(), req.OneTimeKeys)

	httputil.WriteJSON(w, http.StatusOK, ClaimKeysResponse{
		OneTimeKeys: result.OneTimeKeys,
		Failures:    result.Failures,
	})
}

// getKeyChanges retorna os usuários que atualizaram suas chaves de dispositivo desde o último /sync
// GET /_matrix/client/v3/keys/changes
// NOTE: implementação mínima por enquanto, sempre retorna listas vazias
func (h *Handler) getKeyChanges(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, KeyChangesResponse{
		Changed: []string{},
		Left:    []string{},
	})
}
