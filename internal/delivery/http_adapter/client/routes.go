package client

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/account"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/auth"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/media"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/profile"
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

	// sincronização de dados
	mux.Handle("GET /_matrix/client/v3/sync", authMiddleware(http.HandlerFunc(h.syncClient))) // WARN: esse é o dificil
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

	// chaves de encriptação (mock)
	mux.Handle("POST /_matrix/client/v3/keys/upload", authMiddleware(http.HandlerFunc(h.uploadKeys)))
	mux.Handle("POST /_matrix/client/v3/keys/query", authMiddleware(http.HandlerFunc(h.queryKeys)))

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
	if timeout == 0 {
		timeout = 30000 // 30s
	}

	req.Timeout = time.Duration(timeout) * time.Millisecond

	response, err := h.syncService.SyncClient(r.Context(), userID, req.Since, req.Timeout)
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

// uploadKeys lida com o mock de upload de chaves (E2EE) do dispositivo
// POST /_matrix/client/v3/keys/upload
func (h *Handler) uploadKeys(w http.ResponseWriter, r *http.Request) {
	// A especificação exige retornar a contagem de chaves de uso único (One-Time Keys) remanescentes.
	// Fingir que recebemos e salvamos as chaves é o suficiente para parar o spam do cliente.
	response := map[string]any{
		"one_time_key_counts": map[string]int{
			"signed_curve25519": 50, // Dizemos ao Element que ele tem 50 OTKs seguras salvas
		},
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// queryKeys lida com o mock dinâmico de busca por chaves
// POST /_matrix/client/v3/keys/query
func (h *Handler) queryKeys(w http.ResponseWriter, r *http.Request) {
	var req QueryKeysRequest

	// Tentamos ler os usuários que o Element quer consultar.
	// Se falhar ou estiver vazio, ignoramos
	_ = httputil.ParseBody(r, &req)

	deviceKeysResponse := make(map[string]map[string]any)
	for userID := range req.DeviceKeys {
		// Sem dispositivos criptografados
		deviceKeysResponse[userID] = map[string]any{}
	}

	response := map[string]any{
		"device_keys": deviceKeysResponse,
		"failures":    map[string]any{},
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}
