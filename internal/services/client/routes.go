package client

import (
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/repository"
	"github.com/caio-bernardo/dragonite/internal/services/client/auth"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type Handler struct {
	userStore   repository.UserStore
	deviceStore repository.DeviceStore
}

func NewHandler(userStore repository.UserStore, deviceStore repository.DeviceStore) *Handler {
	return &Handler{userStore: userStore, deviceStore: deviceStore}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {

	auth := auth.NewHandler(h.userStore, h.deviceStore)

	mux.HandleFunc("GET /_matrix/client/versions", h.getVersions)

	// autenticação
	auth.RegisterRoutes(mux)

	// sincronização de dados
	mux.HandleFunc("GET /_matrix/client/sync", util.UnimplementedHandler) // WARN: esse é o dificil

	// chats
	mux.HandleFunc("GET /_matrix/client/v3/publicRooms", util.UnimplementedHandler)

	// manipulação de chat
	mux.HandleFunc("POST /_matrix/client/v3/createRoom", util.UnimplementedHandler)
	mux.HandleFunc("POST /_matrix/client/v3/rooms/{roomId}/join", util.UnimplementedHandler)
	mux.HandleFunc("POST /_matrix/client/v3/rooms/{roomId}/leave", util.UnimplementedHandler)

	// troca de eventos
	mux.HandleFunc("PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}", util.UnimplementedHandler)
	mux.HandleFunc("PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}", util.UnimplementedHandler)
}

func (h *Handler) getVersions(w http.ResponseWriter, r *http.Request) {
	response := SupportedVersionsResponse{
		Versions: []string{"r0.0.5", "v1.18"},
	}
	util.WriteJSON(w, 200, response)
}
