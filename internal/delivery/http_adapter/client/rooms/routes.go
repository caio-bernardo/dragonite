package rooms

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/infrastructure"
	"github.com/caio-bernardo/dragonite/internal/usecase"
	"github.com/caio-bernardo/dragonite/internal/util"
)

// Handler agrupa as dependências dos handlers de rooms.
// Mesmo padrão de auth.Handler.
type Handler struct {
	directoryService      *usecase.DirectoryService
	roomAdminService      *usecase.RoomAdminService
	roomMembershipService *usecase.RoomMembershipService
	roomInteractions      *usecase.RoomInteractionService
	idempotencyCache      infrastructure.IdempotencyCache
	serverName            string
}

func NewHandler(
	serverName string,
	directoryService *usecase.DirectoryService,
	roomAdminService *usecase.RoomAdminService,
	roomMembershipService *usecase.RoomMembershipService,
	roomInteractions *usecase.RoomInteractionService,
	idempotencyCache infrastructure.IdempotencyCache,
) *Handler {
	return &Handler{
		serverName:            serverName,
		directoryService:      directoryService,
		roomAdminService:      roomAdminService,
		roomMembershipService: roomMembershipService,
		roomInteractions:      roomInteractions,
		idempotencyCache:      idempotencyCache,
	}
}

// RegisterRoutes registra todas as rotas de rooms no mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware httputil.Middleware) {
	// Não requer autenticação (spec permite listagem pública sem token)
	mux.HandleFunc("GET /_matrix/client/v3/publicRooms", h.getPublicRooms)

	// Requerem autenticação
	mux.Handle("POST /_matrix/client/v3/createRoom", authMiddleware(http.HandlerFunc(h.postCreateRoom)))
	mux.Handle("POST /_matrix/client/v3/rooms/{roomId}/join", authMiddleware(http.HandlerFunc(h.postJoinRoom)))
	mux.Handle("POST /_matrix/client/v3/rooms/{roomId}/leave", authMiddleware(http.HandlerFunc(h.postLeaveRoom)))
	mux.Handle("PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}", authMiddleware(http.HandlerFunc(h.putSendEvent)))
	// com stateKey (ex: /state/m.room.member/@alice:server.com)
	mux.Handle("PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}", authMiddleware(http.HandlerFunc(h.putStateEvent)))
	// sem stateKey — stateKey vazio, trailing slash opcional (ex: /state/m.room.name ou /state/m.room.name/)
	mux.Handle("PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}", authMiddleware(http.HandlerFunc(h.putStateEvent)))
	mux.Handle("PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/", authMiddleware(http.HandlerFunc(h.putStateEvent)))
	mux.Handle("GET /_matrix/client/v3/rooms/{roomId}/messages", authMiddleware(http.HandlerFunc(h.getRoomMessages)))
	// marcação de leitura (mock)
	mux.Handle("POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}", authMiddleware(http.HandlerFunc(h.postReceipt)))
	mux.Handle("POST /_matrix/client/v3/rooms/{roomId}/read_markers", authMiddleware(http.HandlerFunc(h.postReadMarkers)))
}

// getPublicRooms lista as salas públicas do servidor.
// GET /_matrix/client/v3/publicRooms
// Ref: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3publicrooms
func (h *Handler) getPublicRooms(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	// Query params: limit e since (paginação conforme o spec)
	limitStr := r.URL.Query().Get("limit")
	limit := 50 // default do spec
	if limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil || parsed < 0 {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Invalid limit parameter")
			return
		}
		limit = parsed
	}
	since := r.URL.Query().Get("since")
	sinceInt, err := strconv.Atoi(since)
	if err != nil {
		sinceInt = 0
	}

	response, err := h.directoryService.ListPublic(ctx, "", limit, sinceInt)
	if err != nil {
		log.Printf("[ERROR] GET /publicRooms: %v", err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to list rooms")
		return
	}
	httputil.WriteJSON(w, http.StatusOK, response)
}

// postCreateRoom cria uma nova sala para o usuário autenticado.
// POST /_matrix/client/v3/createRoom
// Ref: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3createroom
func (h *Handler) postCreateRoom(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	// Mesmo padrão de postLogout: lê user_id do contexto injetado pelo middleware de auth
	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid access token")
		return
	}

	var req CreateRoomRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		if err == types.ErrNoBodyFound {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "No request body")
		} else {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Invalid request body")
		}
		return
	}

	// Campos opcionais do body: *string -> string, usando "" quando ausentes
	// (a spec permite a omissão de todos eles)
	var alias, name, topic, version string
	if req.RoomAliasName != nil {
		alias = *req.RoomAliasName
	}
	if req.Name != nil {
		name = *req.Name
	}
	if req.Topic != nil {
		topic = *req.Topic
	}
	if req.RoomVersion != nil {
		version = *req.RoomVersion
	}

	// initial_state: converte do formato da requisição (schemas.InitialStateEvent)
	// para o formato esperado pelo usecase (usecase.StateEventParams)
	initialState := make([]usecase.StateEventParams, 0, len(req.InitialState))
	for _, ev := range req.InitialState {
		stateKey := ev.StateKey
		initialState = append(initialState, usecase.StateEventParams{
			StateKey: &stateKey,
			Type:     ev.Type,
			Content:  ev.Content,
		})
	}

	params := usecase.CreateRoomParams{
		CreatorID:    userID,
		Visibility:   req.Visibility,
		Alias:        alias,
		Name:         name,
		Version:      version,
		Topic:        topic,
		Invite:       req.Invite,
		IsDirect:     req.IsDirect,
		InitialState: initialState,
		Preset:       req.Preset,
	}

	canal, err := h.roomAdminService.CreateRoom(ctx, params)
	if err != nil {
		log.Printf("[ERROR] POST /createRoom: %v", err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to create room")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, CreateRoomResponse{RoomID: canal.ID})
}

// postJoinRoom adiciona o usuário autenticado à sala especificada.
// POST /_matrix/client/v3/rooms/{roomId}/join
// Ref: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidjoin
func (h *Handler) postJoinRoom(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid access token")
		return
	}

	// r.PathValue extrai parâmetros de rota do padrão {roomId}
	roomID := r.PathValue("roomId")
	if roomID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing roomId")
		return
	}

	// body é opcional pelo spec; ignoramos erro de parse
	var req JoinRoomRequest
	_ = httputil.ParseBody(r, &req)

	if util.IsRemoteUser(roomID, h.serverName) {
		// Extract the remote server name from the room handle (e.g. extracts "example.com" from "#public:example.com")
		remoteServer := util.ExtractDomainFromUserID(roomID)
		if remoteServer == "" {
			httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "Could not resolve remote server from room identifier")
			return
		}

		// Execute the Outbound Federated Join
		err := h.roomMembershipService.JoinRemoteRoom(ctx, userID, roomID, remoteServer)
		if err != nil {
			log.Printf("[ERROR] POST /rooms/%s/join (Federated): %v", roomID, err)
			httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to federate join remote room")
			return
		}

		httputil.WriteJSON(w, http.StatusOK, JoinRoomResponse{RoomID: roomID})
		return
	}

	err := h.roomMembershipService.JoinLocalRoom(ctx, userID, roomID)
	if err != nil {
		log.Printf("[ERROR] POST /rooms/%s/join: %v", roomID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to join room")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, JoinRoomResponse{RoomID: roomID})
}

// postLeaveRoom remove o usuário autenticado da sala especificada.
// POST /_matrix/client/v3/rooms/{roomId}/leave
// Ref: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidleave
func (h *Handler) postLeaveRoom(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid access token")
		return
	}

	roomID := r.PathValue("roomId")
	if roomID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing roomId")
		return
	}

	// body é opcional pelo spec
	var req LeaveRoomRequest
	_ = httputil.ParseBody(r, &req)

	err := h.roomMembershipService.LeaveRoom(ctx, userID, roomID)
	if err != nil {
		log.Printf("[ERROR] POST /rooms/%s/leave: %v", roomID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to leave room")
		return
	}

	// Spec exige {} com 200 OK — mesmo padrão do postLogout
	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}

// putSendEvent envia um room event para a sala especificada.
// PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
// Ref: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid
func (h *Handler) putSendEvent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	accessToken := httputil.ExtractBearerToken(r)

	// 1. Identity Extraction
	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing access token")
		return
	}

	// 2. Path Parameter Extraction
	roomID := r.PathValue("roomId")
	eventType := r.PathValue("eventType")
	txnID := r.PathValue("txnId")
	endpoint := r.URL.Path

	if roomID == "" || eventType == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing path parameters")
		return
	}

	if eventID, exists := h.idempotencyCache.Get(ctx, accessToken, endpoint, txnID); exists {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{
			"event_id": eventID,
		})
		return
	}

	// 3. Parse Body
	var content map[string]any
	if err := httputil.ParseBody(r, &content); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Invalid JSON body")
		return
	}

	// 4. Map to DTO
	params := usecase.EventParams{
		RoomID:    roomID,
		SenderID:  userID,
		EventType: eventType,
		Content:   content,
	}

	// 5. Execute Core Logic
	eventID, err := h.roomInteractions.SendEvent(ctx, params)
	if err != nil {
		if errors.Is(err, types.ErrForbidden) {
			httputil.WriteMatrixError(w, http.StatusForbidden, httputil.M_FORBIDDEN, "You are not joined to this room")
			return
		}
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to send event")
		return
	}

	// cache this event for 24hours
	_ = h.idempotencyCache.Set(ctx, accessToken, endpoint, txnID, eventID, 24*time.Hour)

	// 6. Return Success
	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"event_id": eventID,
	})
}

// putStateEvent envia um state event para a sala especificada.
// PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}
// Ref: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3roomsroomidstateeventtypestateke
func (h *Handler) putStateEvent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	// 1. Extract Identity
	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing access token")
		return
	}

	// 2. Extract Path Parameters
	roomID := r.PathValue("roomId")
	eventType := r.PathValue("eventType")
	stateKey := r.PathValue("stateKey") // Safe if empty string

	if roomID == "" || eventType == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing required path parameters")
		return
	}

	// 3. Extract JSON Body
	var req StateEventRequest // Read directly into a generic map or your StateEventRequest struct
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Invalid or missing JSON body")
		return
	}

	// 4. Map to Use Case Parameters
	params := usecase.StateParams{
		RoomID:    roomID,
		UserID:    userID,
		EventType: eventType,
		StateKey:  stateKey,
		Content:   req,
	}

	// 5. Execute Business Logic
	eventID, err := h.roomInteractions.SendStateEvent(ctx, params)
	if err != nil {
		// Map domain errors to Matrix HTTP errors
		if errors.Is(err, types.ErrForbidden) {
			httputil.WriteMatrixError(w, http.StatusForbidden, httputil.M_FORBIDDEN, "You do not have permission to send this state event")
			return
		}

		// Fallback for internal errors
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Internal server error")
		return
	}

	// 6. Return Success
	httputil.WriteJSON(w, http.StatusOK, StateEventResponse{EventID: eventID})
}

// getRoomMessages retorna o histórico de eventos de uma sala
// GET /_matrix/client/v3/rooms/{roomId}/messages
// https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3roomsroomidmessages
func (h *Handler) getRoomMessages(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_UNKNOWN_TOKEN, "Missing or invalid access token")
		return
	}

	roomID := r.PathValue("roomId")
	if roomID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing roomId path parameter")
		return
	}

	from := r.URL.Query().Get("from")
	dir := r.URL.Query().Get("dir")

	if dir == "" {
		dir = "b" // "b" (backwards) é o padrão do Matrix
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 10 // Padrão recomendado pelo spec

	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	response, err := h.roomInteractions.GetMessages(ctx, roomID, userID, from, dir, limit)
	if err != nil {
		if errors.Is(err, types.ErrForbidden) {
			httputil.WriteMatrixError(w, http.StatusForbidden, httputil.M_FORBIDDEN, "You do not have permission to read this room's history")
			return
		}
		log.Printf("[ERROR] GET /messages: %v", err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to get room messages")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, response)

}

// postReceipt atualiza o marcador de leitura do utilizador para um determinado evento
// POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
func (h *Handler) postReceipt(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	userID, ok := ctx.Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing access token")
		return
	}

	roomID := r.PathValue("roomId")
	receiptType := r.PathValue("receiptType") // Será "m.read" na maior parte dos casos
	eventID := r.PathValue("eventId")

	if roomID == "" || receiptType == "" || eventID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "Missing required path parameters")
		return
	}

	// Delegar para a regra de negócio
	err := h.roomInteractions.SendReceipt(ctx, userID, roomID, receiptType, eventID)
	if err != nil {
		if errors.Is(err, types.ErrForbidden) {
			httputil.WriteMatrixError(w, http.StatusForbidden, httputil.M_FORBIDDEN, "User is not in the room")
			return
		}
		log.Printf("[ERROR] POST /receipt: %v", err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to update receipt")
		return
	}

	// O spec Matrix exige que se devolva um objeto JSON vazio em caso de sucesso
	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}

// postReadMarkers é um mock para o fully read marker (m.fully_read) e, opcionalmente,
// os read receipts (m.read / m.read.private) enviados no mesmo corpo.
// POST /_matrix/client/v3/rooms/{roomId}/read_markers
func (h *Handler) postReadMarkers(w http.ResponseWriter, r *http.Request) {
	httputil.WriteJSON(w, http.StatusOK, map[string]any{})
}
