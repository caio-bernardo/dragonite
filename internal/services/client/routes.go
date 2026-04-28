package client

import (
	"net/http"
	"os"
	"log"

	"github.com/caio-bernardo/dragonite/internal/repository"
	"github.com/caio-bernardo/dragonite/internal/services/client/auth"
	"github.com/caio-bernardo/dragonite/internal/services/client/rooms"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type Handler struct {
	userStore   repository.UserStore
	deviceStore repository.DeviceStore
	canalStore        repository.ChannelStore       
	usuarioCanalStore repository.UsuarioCanalStore
}

func NewHandler(userStore repository.UserStore, deviceStore repository.DeviceStore, canalStore repository.ChannelStore, usuarioCanalStore repository.UsuarioCanalStore) *Handler {
	return &Handler{userStore: userStore, deviceStore: deviceStore, canalStore: canalStore, usuarioCanalStore: usuarioCanalStore}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware types.Middleware) {

	auth := auth.NewHandler(h.userStore, h.deviceStore)
	roomHandler := rooms.NewHandler(h.canalStore, h.usuarioCanalStore, os.Getenv("SERVER_NAME"))

	mux.HandleFunc("GET /_matrix/client/versions", h.getVersions)

	// autenticação
	auth.RegisterRoutes(mux, authMiddleware)

	// sincronização de dados
	mux.HandleFunc("GET /_matrix/client/sync", util.UnimplementedHandler) // WARN: esse é o dificil

	// chats e manipulação de salas
	roomHandler.RegisterRoutes(mux, authMiddleware)

	// troca de eventos
	mux.HandleFunc("PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}", util.UnimplementedHandler)
	mux.HandleFunc("PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}", util.UnimplementedHandler)

	// busca de usuários
	mux.Handle("POST /_matrix/client/v3/user_directory/search", authMiddleware(http.HandlerFunc(h.searchUsers)))
}

func (h *Handler) getVersions(w http.ResponseWriter, r *http.Request) {
	response := SupportedVersionsResponse{
		Versions: []string{"r0.0.5", "v1.18"},
	}
	util.WriteJSON(w, 200, response)
}

// searchUsers realiza a busca de usuários no diretório.
// POST /_matrix/client/v3/user_directory/search
// Ref: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3user_directorysearch
func (h *Handler) searchUsers(w http.ResponseWriter, r *http.Request) {
	var req UserSearchRequest
	if err := util.ParseBody(r, &req); err != nil {
		if err == types.ErrBodyRequired {
			util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_NOT_JSON, "No request body"))
		} else {
			util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_BAD_JSON, "Invalid request body"))
		}
		return
	}

	if req.SearchTerm == "" {
		util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_BAD_JSON, "search_term is required"))
		return
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 10 // padrão definido pela spec
	}

	// Busca limit+1 para detectar se há mais resultados do que o limite solicitado
	usuarios, err := h.userStore.Search(r.Context(), req.SearchTerm, limit+1)
	if err != nil {
		log.Printf("[ERROR] POST /user_directory/search: %v", err)
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "Search failed"))
		return
	}

	limited := len(usuarios) > limit
	if limited {
		usuarios = usuarios[:limit]
	}

	results := make([]UserSearchResult, len(usuarios))
	for i, u := range usuarios {
		results[i] = UserSearchResult{
			UserID:      u.ID,
			DisplayName: u.Nome,
			AvatarURL:   u.Foto,
		}
	}

	util.WriteJSON(w, http.StatusOK, UserSearchResponse{
		Limited: limited,
		Results: results,
	})
}
