package client

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/notifier"
	"github.com/caio-bernardo/dragonite/internal/repository"
	"github.com/caio-bernardo/dragonite/internal/services/client/auth"
	"github.com/caio-bernardo/dragonite/internal/services/client/rooms"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type Handler struct {
	userStore         repository.UserStore
	deviceStore       repository.DeviceStore
	canalStore        repository.ChannelStore
	usuarioCanalStore repository.UsuarioCanalStore
	eventoStore       repository.EventoStore
	notifier          notifier.Notifier
}

func NewHandler(userStore repository.UserStore, deviceStore repository.DeviceStore, canalStore repository.ChannelStore, usuarioCanalStore repository.UsuarioCanalStore, eventoStore repository.EventoStore, notif notifier.Notifier) *Handler {
	return &Handler{userStore: userStore, deviceStore: deviceStore, canalStore: canalStore, usuarioCanalStore: usuarioCanalStore, eventoStore: eventoStore, notifier: notif}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware types.Middleware) {

	auth := auth.NewHandler(h.userStore, h.deviceStore)
	roomHandler := rooms.NewHandler(h.canalStore, h.usuarioCanalStore, os.Getenv("SERVER_NAME"), h.notifier)

	mux.HandleFunc("GET /_matrix/client/versions", h.getVersions)

	// autenticação
	auth.RegisterRoutes(mux, authMiddleware)

	// sincronização de dados
	mux.Handle("GET /_matrix/v3/client/sync", authMiddleware(http.HandlerFunc(h.syncClient))) // WARN: esse é o dificil

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

// syncClient lida com a sincronização de dados do cliente com o servidor
// Pode ser usado para receber um log inicial após o login e sincronização incremental de alterações.
func (h *Handler) syncClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := ctx.Value(types.UserIDKey).(string)
	// Constroi o corpo da requisição
	var req SyncClientRequest
	req.Since = model.ParseToken(r.FormValue("since"))
	req.Filter = r.FormValue("filter")
	req.FullState = r.FormValue("full_state") == "true"
	req.SetPresence = SetPresence(r.FormValue("set_presence"))
	timeoutStr := r.FormValue("timeout")
	var timeout int
	var err error
	if timeoutStr != "" {
		timeout, err = strconv.Atoi(timeoutStr)
		if err != nil {
			util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_UNKNOWN, "could not parse timeout. Expected integer"))
			return
		}
	}
	req.Timeout = time.Duration(timeout) * time.Millisecond

	// Lógica de Long-Polling
	if req.Since.RoomEvents != 0 {
		hasEvents, err := h.eventoStore.CheckNew(ctx, userID, req.Since)
		if err != nil {
			util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "could not check new events"))
			return
		}

		if !hasEvents && req.Timeout > 0 {
			// sem eventos, long-polling
			ch := h.notifier.Subscribe(userID)
			defer h.notifier.Unsubscribe(userID, ch)

			select {
			case <-ch:
				// Novo evento, pode acessar o banco
			case <-time.After(req.Timeout):
				// Deu timeout antes de um novo evento, cria novo token e retorna
				maxGlobal, _ := h.eventoStore.GetMaxGlobalStreamOrdering(ctx)
				if maxGlobal > req.Since.RoomEvents {
					req.Since.RoomEvents = maxGlobal
				}
				response := createSyncResponse()
				response.NextBatch = req.Since
				util.WriteJSON(w, http.StatusOK, response)
				return
			case <-ctx.Done():
				// o client se desconectou
				return
			}
		}
	}

	// accesso ao banco
	events, newToken, err := h.eventoStore.GetSince(ctx, userID, req.Since)
	if err != nil {
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, "could not get events"))
		return
	}
	// cria a resposta
	response := encodeEventsIntoResponse(events, newToken)

	util.WriteJSON(w, http.StatusOK, response)
}
