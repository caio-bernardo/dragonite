package roomkeys

import (
	"errors"
	"log"
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

// Handler agrupa as rotas de backup de chaves E2EE (room_keys) do cliente Matrix
type Handler struct {
	backupService *usecase.BackupService
}

// NewHandler cria um Handler de room_keys com o serviço injetado
func NewHandler(backupService *usecase.BackupService) *Handler {
	return &Handler{backupService: backupService}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware httputil.Middleware) {
	// TODO: adicionar rate limiting por userID antes do authMiddleware quando
	// a infraestrutura de rate limiting for implementada no projeto.
	mux.Handle("GET /_matrix/client/v3/room_keys/version", authMiddleware(http.HandlerFunc(h.getLatestVersion)))
	mux.Handle("POST /_matrix/client/v3/room_keys/version", authMiddleware(http.HandlerFunc(h.createVersion)))
	mux.Handle("GET /_matrix/client/v3/room_keys/keys", authMiddleware(http.HandlerFunc(h.getRoomKeys)))
	mux.Handle("GET /_matrix/client/v3/room_keys/keys/{roomID}", authMiddleware(http.HandlerFunc(h.getRoomKeys)))
	mux.Handle("PUT /_matrix/client/v3/room_keys/keys", authMiddleware(http.HandlerFunc(h.putRoomKeys)))
	mux.Handle("DELETE /_matrix/client/v3/room_keys/keys", authMiddleware(http.HandlerFunc(h.deleteRoomKeys)))
}

// getLatestVersion retorna informações sobre a versão mais recente do backup de chaves
// GET /_matrix/client/v3/room_keys/version
func (h *Handler) getLatestVersion(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}

	backup, err := h.backupService.GetLatestBackupVersion(r.Context(), userID)
	if err != nil {
		if errors.Is(err, usecase.ErrBackupNotFound) {
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "No current backup version")
			return
		}

		log.Printf("[ERROR] GET /_matrix/client/v3/room_keys/version (user=%s): %v", userID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to fetch backup version")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, BackupVersionResponse{
		Algorithm: backup.Algorithm,
		AuthData:  backup.AuthData,
		Count:     backup.Count,
		ETag:      backup.ETag,
		Version:   backup.VersionString(),
	})
}

// createVersion cria uma nova versão de backup de chaves
// POST /_matrix/client/v3/room_keys/version
func (h *Handler) createVersion(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}

	var req CreateBackupVersionRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Request did not contain valid JSON")
		return
	}

	if req.Algorithm == "" || len(req.AuthData) == 0 {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "Missing algorithm or auth_data")
		return
	}

	backup, err := h.backupService.CreateBackupVersion(r.Context(), usecase.CreateBackupParams{
		UserID:    userID,
		Algorithm: req.Algorithm,
		AuthData:  req.AuthData,
	})
	if err != nil {
		log.Printf("[ERROR] POST /_matrix/client/v3/room_keys/version (user=%s): %v", userID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to create backup version")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, CreateBackupVersionResponse{
		Version: backup.VersionString(),
	})
}

// getRoomKeys retorna todas as chaves armazenadas na versão de backup indicada
// GET /_matrix/client/v3/room_keys/keys
func (h *Handler) getRoomKeys(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}

	version := r.URL.Query().Get("version")
	if version == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "Missing version query parameter")
		return
	}

	keys, err := h.backupService.GetRoomKeys(r.Context(), userID, version)
	if err != nil {
		if errors.Is(err, usecase.ErrBackupNotFound) {
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Unknown backup version")
			return
		}

		log.Printf("[ERROR] GET /_matrix/client/v3/room_keys/keys (user=%s): %v", userID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to fetch room keys")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, GetRoomKeysResponse{Rooms: groupRoomKeys(keys)})
}

// putRoomKeys armazena uma ou mais chaves de sessão na versão de backup atual do usuário
// PUT /_matrix/client/v3/room_keys/keys
func (h *Handler) putRoomKeys(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}

	version := r.URL.Query().Get("version")
	if version == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "Missing version query parameter")
		return
	}

	var req PutRoomKeysRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Request did not contain valid JSON")
		return
	}

	count, etag, err := h.backupService.PutRoomKeys(r.Context(), usecase.PutRoomKeysParams{
		UserID:  userID,
		Version: version,
		Keys:    flattenRoomKeys(req.Rooms),
	})
	if err != nil {
		var wrongVersion *usecase.ErrWrongVersion
		if errors.As(err, &wrongVersion) {
			httputil.WriteJSON(w, http.StatusForbidden, WrongVersionErrorResponse{
				ErrCode:        httputil.M_WRONG_ROOM_KEYS_VERSION,
				Message:        "Wrong backup version.",
				CurrentVersion: wrongVersion.CurrentVersion,
			})
			return
		}
		if errors.Is(err, usecase.ErrBackupNotFound) {
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Unknown backup version")
			return
		}

		log.Printf("[ERROR] PUT /_matrix/client/v3/room_keys/keys (user=%s): %v", userID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to store room keys")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, RoomKeysUpdateResponse{Count: count, ETag: etag})
}

// deleteRoomKeys apaga todas as chaves da versão de backup indicada
// DELETE /_matrix/client/v3/room_keys/keys
func (h *Handler) deleteRoomKeys(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}

	version := r.URL.Query().Get("version")
	if version == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "Missing version query parameter")
		return
	}

	count, etag, err := h.backupService.DeleteRoomKeys(r.Context(), userID, version)
	if err != nil {
		if errors.Is(err, usecase.ErrBackupNotFound) {
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Unknown backup version")
			return
		}

		log.Printf("[ERROR] DELETE /_matrix/client/v3/room_keys/keys (user=%s): %v", userID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to delete room keys")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, RoomKeysUpdateResponse{Count: count, ETag: etag})
}

// groupRoomKeys converte a lista plana de domain.ChaveBackup para o formato aninhado da spec
func groupRoomKeys(keys []domain.ChaveBackup) map[string]RoomKeyBackup {
	rooms := make(map[string]RoomKeyBackup)
	for _, k := range keys {
		backup, ok := rooms[k.IDCanal]
		if !ok {
			backup = RoomKeyBackup{Sessions: make(map[string]RoomKeyBackupData)}
		}
		backup.Sessions[k.IDSessao] = RoomKeyBackupData{
			FirstMessageIndex: k.FirstMessageIndex,
			ForwardedCount:    k.ForwardedCount,
			IsVerified:        k.IsVerified,
			SessionData:       k.SessionData,
		}
		rooms[k.IDCanal] = backup
	}
	return rooms
}

// flattenRoomKeys converte o formato aninhado da spec para a lista plana de domain.ChaveBackup
func flattenRoomKeys(rooms map[string]RoomKeyBackup) []domain.ChaveBackup {
	var keys []domain.ChaveBackup
	for roomID, backup := range rooms {
		for sessionID, data := range backup.Sessions {
			keys = append(keys, domain.ChaveBackup{
				IDCanal:           roomID,
				IDSessao:          sessionID,
				FirstMessageIndex: data.FirstMessageIndex,
				ForwardedCount:    data.ForwardedCount,
				IsVerified:        data.IsVerified,
				SessionData:       data.SessionData,
			})
		}
	}
	return keys
}
