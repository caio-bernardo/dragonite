package client

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/auth"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/profile"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/client/rooms"
	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

type Handler struct {
	userService      *usecase.UsuarioService
	syncService      *usecase.SyncService
	directoryService *usecase.DirectoryService
	profileService   *usecase.ProfileService
	authService      *usecase.AuthService
	roomAdmin        *usecase.RoomAdminService
	roomInteractions *usecase.RoomInteractionService
	serverName       string
}

func NewHandler(
	serverName string,
	authService *usecase.AuthService,
	userStore *usecase.UsuarioService,
	directoryStore *usecase.DirectoryService,
	profileStore *usecase.ProfileService,
	syncStore *usecase.SyncService,
	roomAdmin *usecase.RoomAdminService,
	roomInteractions *usecase.RoomInteractionService,
) *Handler {
	return &Handler{
		serverName:       serverName,
		userService:      userStore,
		directoryService: directoryStore,
		profileService:   profileStore,
		syncService:      syncStore,
		roomAdmin:        roomAdmin,
		roomInteractions: roomInteractions,
		authService:      authService,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware httputil.Middleware) {

	mux.HandleFunc("GET /_matrix/client/versions", h.getVersions)

	// autenticação
	auth := auth.NewHandler(h.authService)
	auth.RegisterRoutes(mux, authMiddleware)

	// chats e manipulação de salas
	roomHandler := rooms.NewHandler(h.serverName, h.directoryService, h.roomAdmin, h.roomInteractions)
	roomHandler.RegisterRoutes(mux, authMiddleware)

	profileHandler := profile.NewHandler(h.profileService)
	profileHandler.RegisterRoutes(mux, authMiddleware)

	// sincronização de dados
	mux.Handle("GET /_matrix/v3/client/sync", authMiddleware(http.HandlerFunc(h.syncClient))) // WARN: esse é o dificil
	// busca de usuários
	mux.Handle("POST /_matrix/client/v3/user_directory/search", authMiddleware(http.HandlerFunc(h.searchUsers)))

}

func (h *Handler) getVersions(w http.ResponseWriter, r *http.Request) {
	response := SupportedVersionsResponse{
		Versions: []string{"r0.0.5", "v1.18"},
	}
	httputil.WriteJSON(w, 200, response)
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
		timeout, err = strconv.Atoi(timeoutStr)
		if err != nil {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_UNKNOWN, "could not parse timeout. Expected integer")
			return
		}
	}
	req.Timeout = time.Duration(timeout) * time.Millisecond
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "could not get events")
		return
	}

	events, newToken, err := h.syncService.SyncClient(r.Context(), userID, req.Since, req.Timeout)

	// cria a resposta
	response := encodeEventsIntoResponse(events, newToken)

	httputil.WriteJSON(w, http.StatusOK, response)
}
