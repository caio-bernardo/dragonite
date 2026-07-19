package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/account"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/auth"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/media"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/presence"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/profile"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/roomkeys"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/rooms"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/infrastructure"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

type Handler struct {
	userService      *usecase.UsuarioService
	syncService      *usecase.SyncService
	directoryService *usecase.DirectoryService
	profileService   *usecase.ProfileService
	accountService   *usecase.AccountService
	authService      *usecase.AuthService
	roomAdmin        *usecase.RoomAdminService
	roomMembership   *usecase.RoomMembershipService
	roomInteractions *usecase.RoomInteractionService
	mediaService     *usecase.MediaService
	idempotencyCache infrastructure.IdempotencyCache
	presenceService  *usecase.PresenceService
	backupService    *usecase.BackupService
	keysService      *usecase.KeysService
	toDeviceService  *usecase.ToDeviceService
	serverName       string
}

func NewHandler(
	serverName string,
	authService *usecase.AuthService,
	userStore *usecase.UsuarioService,
	directoryStore *usecase.DirectoryService,
	profileStore *usecase.ProfileService,
	accountService *usecase.AccountService,
	syncStore *usecase.SyncService,
	roomAdmin *usecase.RoomAdminService,
	roomMembership *usecase.RoomMembershipService,
	roomInteractions *usecase.RoomInteractionService,
	mediaService *usecase.MediaService,
	idempotencyCache infrastructure.IdempotencyCache,
	presenceService *usecase.PresenceService,
	backupService *usecase.BackupService,
	keysService *usecase.KeysService,
	toDeviceService *usecase.ToDeviceService,
) *Handler {
	return &Handler{
		serverName:       serverName,
		userService:      userStore,
		directoryService: directoryStore,
		profileService:   profileStore,
		accountService:   accountService,
		syncService:      syncStore,
		roomAdmin:        roomAdmin,
		roomMembership:   roomMembership,
		roomInteractions: roomInteractions,
		authService:      authService,
		mediaService:     mediaService,
		idempotencyCache: idempotencyCache,
		presenceService:  presenceService,
		backupService:    backupService,
		keysService:      keysService,
		toDeviceService:  toDeviceService,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware httputil.Middleware) {

	mux.HandleFunc("GET /_matrix/client/versions", h.getVersions)

	// autenticação
	auth := auth.NewHandler(h.authService)
	auth.RegisterRoutes(mux, authMiddleware)

	// chats e manipulação de salas
	roomHandler := rooms.NewHandler(h.serverName, h.directoryService, h.roomAdmin, h.roomMembership, h.roomInteractions, h.idempotencyCache)
	roomHandler.RegisterRoutes(mux, authMiddleware)

	profileHandler := profile.NewHandler(h.profileService)
	profileHandler.RegisterRoutes(mux, authMiddleware)

	// account data
	accountHandler := account.NewHandler(h.accountService)
	accountHandler.RegisterRoutes(mux, authMiddleware)

	// upload de mídia
	mediaHandler := media.NewHandler(h.mediaService)
	mediaHandler.RegisterRoutes(mux, authMiddleware)

	// presence (online/offline/unavailable)
	presenceHandler := presence.NewHandler(h.presenceService)
	presenceHandler.RegisterRoutes(mux, authMiddleware)

	// E2EE: backup de chaves + gerenciamento de chaves de dispositivo
	roomKeysHandler := roomkeys.NewHandler(h.backupService, h.keysService)
	roomKeysHandler.RegisterRoutes(mux, authMiddleware)

	// sincronização de dados
	mux.Handle("GET /_matrix/client/v3/sync", authMiddleware(http.HandlerFunc(h.syncClient))) // WARN: esse é o dificil
	mux.Handle("PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}", authMiddleware(http.HandlerFunc(h.sendToDevice)))
	// busca de usuários
	mux.Handle("POST /_matrix/client/v3/user_directory/search", authMiddleware(http.HandlerFunc(h.searchUsers)))
	// salas em que o usuário está atualmente
	mux.Handle("GET /_matrix/client/v3/joined_rooms", authMiddleware(http.HandlerFunc(h.getJoinedRooms)))
	// regras de notificação (mock)
	mux.Handle("GET /_matrix/client/v3/pushrules/", authMiddleware(http.HandlerFunc(h.getPushRules)))
	// upload/leitura de filtro (mock)
	mux.Handle("POST /_matrix/client/v3/user/{userId}/filter", authMiddleware(http.HandlerFunc(h.uploadFilter)))
	mux.Handle("GET /_matrix/client/v3/user/{userId}/filter/{filterId}", authMiddleware(http.HandlerFunc(h.getFilter)))
	// capacidades (mock)
	mux.Handle("GET /_matrix/client/v3/capabilities", authMiddleware(http.HandlerFunc(h.getCapabilities)))

	// directory de aliases de sala
	mux.HandleFunc("GET /_matrix/client/v3/directory/room/{roomAlias}", h.resolveRoomAlias)
	mux.Handle("PUT /_matrix/client/v3/directory/room/{roomAlias}", authMiddleware(http.HandlerFunc(h.setRoomAlias)))
	mux.Handle("DELETE /_matrix/client/v3/directory/room/{roomAlias}", authMiddleware(http.HandlerFunc(h.deleteRoomAlias)))

}

func (h *Handler) getVersions(w http.ResponseWriter, r *http.Request) {
	response := SupportedVersionsResponse{
		Versions: []string{
			"r0.0.1",
			"r0.1.0",
			"r0.2.0",
			"r0.3.0",
			"r0.4.0",
			"r0.5.0",
			"r0.6.0",
			"r0.6.1", // Legacy standard
			"v1.1",
			"v1.2",
			"v1.3",
			"v1.4",
			"v1.5",
			"v1.6",
			"v1.8",
			"v1.9",
			"v1.11", // Current standard support in many clients
			"v1.18",
		},
		UnstableFeatures: map[string]bool{
			"org.matrix.msc2967.refresh_tokens": true,
		},
	}
	httputil.WriteJSON(w, 200, response)
}

// getPushRules retorna um mock vazio das regras de notificação do usuário
// GET /_matrix/client/v3/pushrules/
func (h *Handler) getPushRules(w http.ResponseWriter, r *http.Request) {
	response := PushRulesResponse{
		Global: map[string]any{},
	}
	httputil.WriteJSON(w, http.StatusOK, response)
}

// uploadFilter é um mock que aceita uma definição de filtro e retorna um filter_id fixo
// POST /_matrix/client/v3/user/{userId}/filter
func (h *Handler) uploadFilter(w http.ResponseWriter, r *http.Request) {
	var reqBody map[string]any
	if err := httputil.ParseBody(r, &reqBody); err != nil {
		if err == types.ErrNoBodyFound {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "No request body")
		} else {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Invalid request body")
		}
		return
	}

	httputil.WriteJSON(w, http.StatusOK, FilterUploadResponse{
		FilterID: "0",
	})
}

// getFilter é um mock que retorna um filtro com base no filter_id
// GET /_matrix/client/v3/user/{userId}/filter/{filterId}
// Ref: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3useruseridfilterfilterid
func (h *Handler) getFilter(w http.ResponseWriter, r *http.Request) {
	loggedUser := r.Context().Value(types.UserIDKey).(string)
	userId := r.PathValue("userId")

	if loggedUser != userId {
		httputil.WriteMatrixError(w, http.StatusForbidden, httputil.M_FORBIDDEN, "User not authorized")
		return
	}
	_ = r.PathValue("filterId")

	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}

// getCapabilities é um mock que retorna apenas a capability obrigatória pela spec (m.room_versions)
// GET /_matrix/client/v3/capabilities
// Ref: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3capabilities
func (h *Handler) getCapabilities(w http.ResponseWriter, r *http.Request) {
	response := CapabilitiesResponse{
		Capabilities: Capabilities{
			RoomVersions: RoomVersionsCapability{
				Default: "11",
				Available: map[string]string{
					"11": "stable",
				},
			},
		},
	}
	httputil.WriteJSON(w, http.StatusOK, response)
}

// searchUsers realiza a busca de usuários no diretório.
// POST /_matrix/client/v3/user_directory/search
// Ref: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3user_directorysearch
func (h *Handler) searchUsers(w http.ResponseWriter, r *http.Request) {
	var req UserSearchRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		if err == types.ErrNoBodyFound {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "No request body")
		} else {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Invalid request body")
		}
		return
	}

	if req.SearchTerm == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "search_term is required")
		return
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 10 // padrão definido pela spec
	}

	usuarios, err := h.directoryService.SearchProfiles(r.Context(), req.SearchTerm, limit)
	if err != nil {
		log.Printf("[ERROR] POST /user_directory/search: %v", err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Search failed")
		return
	}

	limited := len(usuarios) > limit
	if limited {
		usuarios = usuarios[:limit]
	}

	results := make([]UserSearchResult, len(usuarios))
	for i, u := range usuarios {
		results[i] = UserSearchResult{
			UserID:      u.IDUsuario,
			DisplayName: *u.DisplayName,
			AvatarURL:   *u.AvatarURL,
		}
	}

	httputil.WriteJSON(w, http.StatusOK, UserSearchResponse{
		Limited: limited,
		Results: results,
	})
}

// getJoinedRooms retorna a lista de salas em que o usuário autenticado tem membership "join"
// GET /_matrix/client/v3/joined_rooms
func (h *Handler) getJoinedRooms(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(types.UserIDKey).(string)

	roomIDs, err := h.roomMembership.GetJoinedRooms(r.Context(), userID)
	if err != nil {
		log.Printf("[ERROR] GET /joined_rooms: %v", err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "failed to fetch joined rooms")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, JoinedRoomsResponse{
		JoinedRooms: roomIDs,
	})
}

// syncClient lida com a sincronização de dados do cliente com o servidor
// Pode ser usado para receber um log inicial após o login e sincronização incremental de alterações.
func (h *Handler) syncClient(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(types.UserIDKey).(string)
	deviceID, _ := r.Context().Value(types.DeviceIDKey).(string)

	// Constroi o corpo da requisição
	var req SyncClientRequest
	req.Since = domain.ParseToken(r.FormValue("since"))
	req.Filter = r.FormValue("filter")
	req.FullState = r.FormValue("full_state") == "true"
	req.SetPresence = SetPresence(r.FormValue("set_presence"))

	timeoutStr := r.FormValue("timeout")
	var timeout int
	var err error
	if timeoutStr != "" {
		parsedTimeout, err := strconv.Atoi(timeoutStr)
		if err != nil {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_UNKNOWN, "could not parse timeout. Expected integer")
			return
		}
		timeout = parsedTimeout
	}
	req.Timeout = time.Duration(timeout) * time.Millisecond

	response, err := h.syncService.SyncClient(r.Context(), userID, deviceID, req.Since, req.Timeout)
	if err != nil {
		if r.Context().Err() == context.Canceled {
			w.WriteHeader(499)
			return
		}
		log.Printf("[%s] [ERROR] SyncClient: %s", time.Now().Format("2006-01-02 15:04:05"), err.Error())
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, fmt.Errorf("could not get events: %w", err).Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// sendToDevice envia mensagens de sinalização diretamente a dispositivos específicos, sem
// persistir no DAG da sala (majoritariamente usado pra troca de chaves E2EE)
// PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
func (h *Handler) sendToDevice(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(types.UserIDKey).(string)
	eventType := r.PathValue("eventType")
	txnID := r.PathValue("txnId")

	if eventType == "" || txnID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "Missing eventType or txnId")
		return
	}

	accessToken := r.Header.Get("Authorization")
	const endpoint = "sendToDevice"
	if _, found := h.idempotencyCache.Get(r.Context(), accessToken, endpoint, txnID); found {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{})
		return
	}

	var req SendToDeviceRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Request did not contain valid JSON")
		return
	}

	err := h.toDeviceService.Send(r.Context(), usecase.SendParams{
		Sender:    userID,
		EventType: eventType,
		Messages:  req.Messages,
	})
	if err != nil {
		log.Printf("[ERROR] PUT /_matrix/client/v3/sendToDevice/%s/%s (user=%s): %v", eventType, txnID, userID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to send messages")
		return
	}

	if err := h.idempotencyCache.Set(r.Context(), accessToken, endpoint, txnID, "ok", 24*time.Hour); err != nil {
		log.Printf("[WARN] PUT /_matrix/client/v3/sendToDevice/%s/%s: failed to set idempotency cache: %v", eventType, txnID, err)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}

// resolveRoomAlias resolve um alias de sala pra room_id + servidores conhecidos
// GET /_matrix/client/v3/directory/room/{roomAlias}
func (h *Handler) resolveRoomAlias(w http.ResponseWriter, r *http.Request) {
	alias := r.PathValue("roomAlias")

	roomID, servers, err := h.directoryService.ResolveAlias(r.Context(), alias)
	if err != nil {
		switch {
		case errors.Is(err, types.ErrNotFound):
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, fmt.Sprintf("Room alias %s not found.", alias))
		case errors.Is(err, types.ErrInvalidParam):
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "Room alias invalid")
		default:
			log.Printf("[ERROR] GET /directory/room/%s: %v", alias, err)
			httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "failed to resolve alias")
		}
		return
	}

	httputil.WriteJSON(w, http.StatusOK, RoomAliasResponse{
		RoomID:  roomID,
		Servers: servers,
	})
}

// setRoomAlias cria um mapeamento de alias -> room_id
// PUT /_matrix/client/v3/directory/room/{roomAlias}
func (h *Handler) setRoomAlias(w http.ResponseWriter, r *http.Request) {
	alias := r.PathValue("roomAlias")

	var req SetRoomAliasRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		if err == types.ErrNoBodyFound {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "No request body")
		} else {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Invalid request body")
		}
		return
	}

	if req.RoomID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "room_id is required")
		return
	}

	if err := h.directoryService.CreateAlias(r.Context(), alias, req.RoomID); err != nil {
		switch {
		case errors.Is(err, types.ErrInvalidParam):
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "Room alias invalid")
		case errors.Is(err, types.ErrAlreadyInUse):
			httputil.WriteMatrixError(w, http.StatusConflict, httputil.M_UNKNOWN, fmt.Sprintf("Room alias %s already exists.", alias))
		default:
			log.Printf("[ERROR] PUT /directory/room/%s: %v", alias, err)
			httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "failed to create alias")
		}
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}

// deleteRoomAlias remove o mapeamento de um alias
// DELETE /_matrix/client/v3/directory/room/{roomAlias}
func (h *Handler) deleteRoomAlias(w http.ResponseWriter, r *http.Request) {
	alias := r.PathValue("roomAlias")

	if err := h.directoryService.DeleteAlias(r.Context(), alias); err != nil {
		switch {
		case errors.Is(err, types.ErrNotFound):
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, fmt.Sprintf("Room alias %s not found.", alias))
		case errors.Is(err, types.ErrInvalidParam):
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "Room alias invalid")
		default:
			log.Printf("[ERROR] DELETE /directory/room/%s: %v", alias, err)
			httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "failed to delete alias")
		}
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}
