package client

import (
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/services/client/auth"
	"github.com/caio-bernardo/dragonite/internal/utils"
)

type Handler struct {
}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	auth := auth.NewHandler()

	mux.HandleFunc("GET /_matrix/client/versions", h.getVersions)
	// autenticação

	auth.RegisterRoutes(mux)

	// sincronização de dados
	mux.HandleFunc("GET /_matrix/client/sync", utils.UnimplementedHandler) // WARN: esse é o dificil

	// chats
	mux.HandleFunc("GET /_matrix/client/v3/publicRooms", utils.UnimplementedHandler)

	// manipulação de chat
	mux.HandleFunc("POST /_matrix/client/v3/createRoom", utils.UnimplementedHandler)
	mux.HandleFunc("POST /_matrix/client/v3/rooms/{roomId}/join", utils.UnimplementedHandler)
	mux.HandleFunc("POST /_matrix/client/v3/rooms/{roomId}/leave", utils.UnimplementedHandler)

	// troca de eventos
	mux.HandleFunc("PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}", utils.UnimplementedHandler)
	mux.HandleFunc("PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}", utils.UnimplementedHandler)
}

func (h *Handler) getVersions(w http.ResponseWriter, r *http.Request) {
	response := SupportedVersionsResponse{
		Versions: []string{"r0.0.5", "v1.18"},
	}
	utils.WriteJSON(w, 200, response)
}
