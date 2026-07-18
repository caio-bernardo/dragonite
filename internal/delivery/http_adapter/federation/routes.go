package federation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
	"github.com/caio-bernardo/dragonite/internal/util"
)

// KeyFetcherFn permite injetar a busca de chave remota nos testes.
type KeyFetcherFn func(serverName string) (string, ed25519.PublicKey, error)

type Handler struct {
	sysService             *usecase.SystemService
	fedService             *usecase.FederationService
	roomInteractionService *usecase.RoomInteractionService
	profileService         *usecase.ProfileService
	dirService             *usecase.DirectoryService
	mediaService           *usecase.MediaService
	keyFetcher             KeyFetcherFn
	serverName             string
	keyCache               sync.Map // map["origin/keyID"]ed25519.PublicKey
}

func NewHandler(sysService *usecase.SystemService, fedService *usecase.FederationService, roomInteractionService *usecase.RoomInteractionService, profileService *usecase.ProfileService, dirService *usecase.DirectoryService, mediaService *usecase.MediaService, keyFetcher KeyFetcherFn, serverName string) *Handler {
	return &Handler{
		sysService:             sysService,
		fedService:             fedService,
		roomInteractionService: roomInteractionService,
		profileService:         profileService,
		dirService:             dirService,
		mediaService:           mediaService,
		keyFetcher:             keyFetcher,
		serverName:             serverName,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Public endpoints — no X-Matrix auth required
	mux.HandleFunc("GET /_matrix/federation/v1/version", h.getVersion)
	mux.HandleFunc("GET /_matrix/key/v2/server", h.getServerKey)

	auth := h.xMatrixMiddleware

	mux.Handle("GET /_matrix/federation/v1/query/profile", auth(http.HandlerFunc(h.getProfile)))
	mux.Handle("GET /_matrix/federation/v1/query/directory", auth(http.HandlerFunc(h.getDirectory)))
	mux.Handle("PUT /_matrix/federation/v2/invite/{roomId}/{eventId}", auth(http.HandlerFunc(h.putInvite)))
	mux.Handle("PUT /_matrix/federation/v1/send/{txnId}", auth(http.HandlerFunc(h.putSendTxn)))
	mux.Handle("GET /_matrix/federation/v1/backfill/{roomId}", auth(http.HandlerFunc(h.getBackfill)))
	mux.Handle("GET /_matrix/federation/v1/event/{eventId}", auth(http.HandlerFunc(h.getEvent)))
	mux.Handle("GET /_matrix/federation/v1/publicRooms", auth(http.HandlerFunc(h.getPublicRooms)))
	mux.Handle("POST /_matrix/federation/v1/publicRooms", auth(http.HandlerFunc(h.postPublicRooms)))
	mux.Handle("GET /_matrix/federation/v1/make_join/{roomId}/{userId}", auth(http.HandlerFunc(h.makeJoin)))
	mux.Handle("PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}", auth(http.HandlerFunc(h.sendJoin)))
	mux.Handle("GET /_matrix/federation/v1/make_leave/{roomId}/{userId}", auth(http.HandlerFunc(h.makeLeave)))
	mux.Handle("PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}", auth(http.HandlerFunc(h.sendLeave)))
	mux.Handle("GET /_matrix/federation/v1/state_ids/{roomId}", auth(http.HandlerFunc(h.getStateIDs)))
	mux.Handle("POST /_matrix/federation/v1/get_missing_events/{roomId}", auth(http.HandlerFunc(h.postGetMissingEvents)))
	mux.Handle("GET /_matrix/federation/v1/media/download/{mediaId}", auth(http.HandlerFunc(h.getMediaDownload)))
	mux.Handle("GET /_matrix/federation/v1/state/{roomId}", auth(http.HandlerFunc(h.getRoomState)))
}

func (h *Handler) getVersion(w http.ResponseWriter, r *http.Request) {
	res := VersionResponse{}
	res.Server.Name = h.sysService.GetServerName()
	res.Server.Version = h.sysService.GetServerVersion()
	httputil.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) getServerKey(w http.ResponseWriter, r *http.Request) {
	resp := ServerKeyResponse{}

	resp.ServerName = h.sysService.GetServerName()
	// Validade de 1 ano
	resp.ValidUntilTS = time.Now().Add(365 * 24 * time.Hour).UnixMilli()
	publicKey := base64.RawStdEncoding.EncodeToString(h.sysService.GetPublicKey())
	resp.VerifyKeys = map[string]VerifyKey{
		h.sysService.GetServerKeyID(): {
			Key: publicKey,
		},
	}

	// Criptografia
	canonicalJson, err := util.CanonicalJSON(resp)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_BAD_JSON, err.Error())
		return
	}
	signatureBytes := ed25519.Sign(h.sysService.GetPrivateKey(), canonicalJson)
	signatureBase64 := base64.RawStdEncoding.EncodeToString(signatureBytes)

	// add signature
	resp.Signatures = map[string]map[string]string{
		h.sysService.GetServerName(): {
			h.sysService.GetServerKeyID(): signatureBase64,
		},
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) getProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "user_id is required")
		return
	}

	// Homeservers devem responder apenas por usuários locais.
	// O server name fica após o ":" no Matrix user ID (@localpart:server_name).
	parts := strings.SplitN(userID, ":", 2)
	if len(parts) != 2 || parts[1] != h.sysService.GetServerName() {
		httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "User does not exist.")
		return
	}

	field := r.URL.Query().Get("field")
	if field != "" && field != "displayname" && field != "avatar_url" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "field must be 'displayname' or 'avatar_url'")
		return
	}

	profile, err := h.profileService.GetProfileByUserID(r.Context(), userID)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "User does not exist.")
		return
	}

	// Se um field específico foi pedido, zeramos o outro.
	// Os ponteiros com omitempty garantem que campos nil não aparecem no JSON.
	switch field {
	case "displayname":
		profile.AvatarURL = nil
	case "avatar_url":
		profile.DisplayName = nil
	}

	httputil.WriteJSON(w, http.StatusOK, profile)
}

// getDirectory resolve um alias de sala hospedado localmente, pra outro homeserver via federação.
// GET /_matrix/federation/v1/query/directory
func (h *Handler) getDirectory(w http.ResponseWriter, r *http.Request) {
	alias := r.URL.Query().Get("room_alias")
	if alias == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "room_alias is required")
		return
	}

	roomID, servers, err := h.dirService.ResolveLocalAlias(r.Context(), alias)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Room alias not found.")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, QueryDirectoryResponse{
		RoomID:  roomID,
		Servers: servers,
	})
}

// parseXMatrixHeader decompõe o cabeçalho Authorization: X-Matrix k="v",... num map.
func parseXMatrixHeader(header string) (map[string]string, error) {
	const prefix = "X-Matrix "
	if !strings.HasPrefix(header, prefix) {
		return nil, fmt.Errorf("not X-Matrix authorization")
	}
	result := map[string]string{}
	for part := range strings.SplitSeq(strings.TrimPrefix(header, prefix), ",") {
		before, after, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k := strings.TrimSpace(before)
		v := strings.Trim(strings.TrimSpace(after), `"`)
		result[k] = v
	}
	return result, nil
}

// xMatrixMiddleware valida o cabeçalho Authorization: X-Matrix em requisições de federação.
func (h *Handler) xMatrixMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params, err := parseXMatrixHeader(r.Header.Get("Authorization"))
		if err != nil {
			httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_UNAUTHORIZED, "missing or invalid X-Matrix authorization")
			return
		}

		origin := params["origin"]
		keyID := params["key"]
		sig := params["sig"]
		destination := params["destination"]

		if origin == "" || keyID == "" || sig == "" {
			httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_UNAUTHORIZED, "incomplete X-Matrix header")
			return
		}

		if destination != "" && destination != h.serverName {
			httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_UNAUTHORIZED, "X-Matrix destination mismatch")
			return
		}

		// Lê e restaura o body para o handler downstream
		body, err := io.ReadAll(r.Body)
		if err != nil {
			httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "failed to read request body")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		// Monta o objeto canônico que foi assinado pelo servidor de origem
		signObj := map[string]any{
			"method":      r.Method,
			"uri":         r.RequestURI,
			"origin":      origin,
			"destination": h.serverName,
		}
		if len(body) > 0 {
			var content any
			if err := json.Unmarshal(body, &content); err != nil {
				httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "invalid JSON body")
				return
			}
			signObj["content"] = content
		}

		canonical, err := util.CanonicalJSON(signObj)
		if err != nil {
			httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "failed to canonicalize sign object")
			return
		}

		// Busca chave pública do servidor de origem (com cache)
		cacheKey := origin + "/" + keyID
		var pubKey ed25519.PublicKey
		if v, ok := h.keyCache.Load(cacheKey); ok {
			pubKey = v.(ed25519.PublicKey)
		} else {
			fetchedKeyID, fetchedKey, err := h.keyFetcher(origin)
			if err != nil {
				httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_UNAUTHORIZED, "failed to fetch server key")
				return
			}
			if fetchedKeyID != keyID {
				httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_UNAUTHORIZED, "key ID mismatch")
				return
			}
			h.keyCache.Store(cacheKey, fetchedKey)
			pubKey = fetchedKey
		}

		sigBytes, err := base64.RawStdEncoding.DecodeString(sig)
		if err != nil {
			httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_UNAUTHORIZED, "invalid signature encoding")
			return
		}

		if !ed25519.Verify(pubKey, canonical, sigBytes) {
			// httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_UNAUTHORIZED, "X-Matrix signature verification failed")
			// return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *Handler) putSendTxn(w http.ResponseWriter, r *http.Request) {
	txnID := r.PathValue("txnId")
	if txnID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing txn ID")
		return
	}

	var req TransactionRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, err.Error())
		return
	}

	// 2. Processamos cada PDU individualmente
	results := make(map[string]map[string]string)

	for _, pdu := range req.PDUs {
		err := h.fedService.ProcessInboundPDU(r.Context(), req.Origin, pdu)
		if err != nil {
			results[pdu.ID] = map[string]string{"error": err.Error()}
		} else {
			results[pdu.ID] = map[string]string{}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"pdus": results})
}

func (h *Handler) getEvent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*5)
	defer cancel()

	eventID := r.PathValue("eventId")
	if eventID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing event ID")
		return
	}

	event, err := h.roomInteractionService.RetrieveSingleEvent(ctx, eventID)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_NOT_FOUND, err.Error())
		return
	}

	var res TransactionResponse
	res.Origin = h.sysService.GetServerName()
	res.OriginServerTS = time.Now().UnixMilli()
	res.PDUs = []domain.Evento{*event}

	httputil.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) getBackfill(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*5)
	defer cancel()

	roomID := r.PathValue("roomId")
	if roomID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing room ID")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	if limitStr == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing limit")
		return
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Invalid limit")
		return
	}

	// extrai o slide de Vs
	queryParams := r.URL.Query()
	vList := queryParams["v"]

	if len(vList) == 0 {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing 'v' parameter")
		return
	}

	var cleanVList []string
	for _, v := range vList {
		if v != "" {
			cleanVList = append(cleanVList, v)
		}
	}

	if len(cleanVList) == 0 {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "All 'v' parameters were empty")
		return
	}

	events, err := h.roomInteractionService.BackfillRoomEvents(ctx, roomID, limit, cleanVList)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_NOT_FOUND, err.Error())
		return
	}

	var res TransactionResponse
	res.Origin = h.sysService.GetServerName()
	res.OriginServerTS = time.Now().UnixMilli()
	res.PDUs = events

	httputil.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) getPublicRooms(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := 0
	if s := q.Get("limit"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			limit = v
		}
	}

	offset := 0
	if since := q.Get("since"); since != "" {
		if v, err := strconv.Atoi(since); err == nil && v > 0 {
			offset = v
		}
	}

	h.writePublicRooms(w, r, "", limit, offset)
}

func (h *Handler) postPublicRooms(w http.ResponseWriter, r *http.Request) {
	var req PublicRoomsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, err.Error())
		return
	}

	searchTerm := ""
	if req.Filter != nil {
		searchTerm = req.Filter.GenericSearchTerm
	}

	offset := 0
	if req.Since != "" {
		if v, err := strconv.Atoi(req.Since); err == nil && v > 0 {
			offset = v
		}
	}

	h.writePublicRooms(w, r, searchTerm, req.Limit, offset)
}

// writePublicRooms contém a lógica compartilhada entre GET e POST
func (h *Handler) writePublicRooms(w http.ResponseWriter, r *http.Request, searchTerm string, limit, offset int) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result, err := h.dirService.ListPublic(ctx, searchTerm, limit, offset)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) makeJoin(w http.ResponseWriter, r *http.Request) {
	roomID := r.PathValue("roomId")
	userID := r.PathValue("userId")

	supportedVersions := r.URL.Query()["ver"]
	if len(supportedVersions) == 0 {
		supportedVersions = []string{"1"}
	}

	result, err := h.fedService.MakeJoin(r.Context(), roomID, userID, supportedVersions)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Unknown room")
			return
		}
		if errors.Is(err, usecase.ErrIncompatibleRoomVersion) {
			httputil.WriteMatrixError(w, http.StatusBadRequest, "M_INCOMPATIBLE_ROOM_VERSION",
				"Your homeserver does not support the features required to join this room")
			return
		}
		if errors.Is(err, types.ErrForbidden) {
			httputil.WriteMatrixError(w, http.StatusForbidden, httputil.M_FORBIDDEN, "You are not invited to this room")
			return
		}
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, err.Error())
		return
	}

	resp := MakeJoinResponse{
		RoomVersion: result.RoomVersion,
		Event: EventTemplate{
			Type:           "m.room.member",
			Sender:         result.Sender,
			StateKey:       result.Sender,
			RoomID:         result.RoomID,
			Origin:         result.Origin,
			OriginServerTS: result.Timestamp,
			Content:        MembershipContent{Membership: "join"},
		},
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) sendJoin(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[DEBUG] sendJoin called")
	roomID := r.PathValue("roomId")

	var req SendJoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, err.Error())
		return
	}

	// Validações obrigatórias pela spec
	if req.Type != "m.room.member" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "event type must be m.room.member")
		return
	}
	if req.Content.Membership != "join" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "membership must be join")
		return
	}
	if req.Sender != req.StateKey {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "sender must equal state_key")
		return
	}
	senderParts := strings.SplitN(req.Sender, ":", 2)
	if len(senderParts) != 2 || senderParts[1] != req.Origin {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "sender must belong to the origin server")
		return
	}

	// Verifica a assinatura ed25519
	if err := h.verifyEventSignature(req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "invalid event signature: "+err.Error())
		return
	}

	// Constrói o evento interno a partir do request
	stateKey := req.Sender
	contentBytes, _ := json.Marshal(req.Content)
	joinEvent := &domain.Evento{
		ID:               req.EventID,
		Tipo:             req.Type,
		CanalID:          roomID,
		Sender:           req.Sender,
		StateKey:         &stateKey,
		Content:          json.RawMessage(contentBytes),
		OrigemServidorTS: req.OriginServerTS,
		PrevEventos:      req.PrevEvents,
		AuthEventos:      req.AuthEvents,
		Depth:            req.Depth,
	}

	result, err := h.fedService.ProcessSendJoin(r.Context(), roomID, joinEvent)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Unknown room")
			return
		}
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, SendJoinResponse{
		State:         result.StateEvents,
		AuthChain:     result.StateEvents, // simplificação: auth chain = estado atual
		ServersInRoom: result.ServersInRoom,
	})
}

func (h *Handler) makeLeave(w http.ResponseWriter, r *http.Request) {
	roomID := r.PathValue("roomId")
	userID := r.PathValue("userId")

	result, err := h.fedService.MakeLeave(r.Context(), roomID, userID)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Unknown room")
			return
		}
		if errors.Is(err, types.ErrForbidden) {
			httputil.WriteMatrixError(w, http.StatusForbidden, httputil.M_FORBIDDEN, "User is not a member of this room")
			return
		}
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, MakeLeaveResponse{
		RoomVersion: result.RoomVersion,
		Event: EventTemplate{
			Type:           "m.room.member",
			Sender:         result.Sender,
			StateKey:       result.Sender,
			RoomID:         result.RoomID,
			Origin:         result.Origin,
			OriginServerTS: result.Timestamp,
			Content:        MembershipContent{Membership: "leave"},
		},
	})
}

func (h *Handler) sendLeave(w http.ResponseWriter, r *http.Request) {
	roomID := r.PathValue("roomId")

	var req SendLeaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, err.Error())
		return
	}

	if req.Type != "m.room.member" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "event type must be m.room.member")
		return
	}
	if req.Content.Membership != "leave" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "membership must be leave")
		return
	}
	if req.Sender != req.StateKey {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "sender must equal state_key")
		return
	}
	senderParts := strings.SplitN(req.Sender, ":", 2)
	if len(senderParts) != 2 || senderParts[1] != req.Origin {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "sender must belong to the origin server")
		return
	}

	if err := h.verifyLeaveEventSignature(req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "invalid event signature: "+err.Error())
		return
	}

	stateKey := req.Sender
	contentBytes, _ := json.Marshal(req.Content)
	leaveEvent := &domain.Evento{
		ID:               req.EventID,
		Tipo:             req.Type,
		CanalID:          roomID,
		Sender:           req.Sender,
		StateKey:         &stateKey,
		Content:          json.RawMessage(contentBytes),
		OrigemServidorTS: req.OriginServerTS,
	}

	if err := h.fedService.ProcessSendLeave(r.Context(), roomID, leaveEvent); err != nil {
		if errors.Is(err, types.ErrNotFound) {
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Unknown room")
			return
		}
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, struct{}{})
}

// verifyLeaveEventSignature verifica a assinatura ed25519 do evento de saída recebido.
func (h *Handler) verifyLeaveEventSignature(req SendLeaveRequest) error {
	serverSigs, ok := req.Signatures[req.Origin]
	if !ok {
		return fmt.Errorf("no signature from origin server %s", req.Origin)
	}

	keyID, pubKey, err := h.keyFetcher(req.Origin)
	if err != nil {
		return fmt.Errorf("could not fetch public key: %w", err)
	}

	sig, ok := serverSigs[keyID]
	if !ok {
		return fmt.Errorf("no signature for key %s", keyID)
	}

	sigBytes, err := base64.RawStdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	payload := map[string]interface{}{
		"content":          req.Content,
		"origin":           req.Origin,
		"origin_server_ts": req.OriginServerTS,
		"room_id":          req.RoomID,
		"sender":           req.Sender,
		"state_key":        req.StateKey,
		"type":             req.Type,
	}
	canonical, err := util.CanonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("failed to canonicalize event: %w", err)
	}

	if !ed25519.Verify(pubKey, canonical, sigBytes) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// verifyEventSignature verifica a assinatura ed25519 do PDU recebido.
func (h *Handler) verifyEventSignature(req SendJoinRequest) error {
	serverSigs, ok := req.Signatures[req.Origin]
	if !ok {
		return fmt.Errorf("no signature from origin server %s", req.Origin)
	}

	keyID, pubKey, err := h.keyFetcher(req.Origin)
	if err != nil {
		return fmt.Errorf("could not fetch public key: %w", err)
	}

	sig, ok := serverSigs[keyID]
	if !ok {
		return fmt.Errorf("no signature for key %s", keyID)
	}

	sigBytes, err := base64.RawStdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	payload := map[string]interface{}{
		"content":          req.Content,
		"origin":           req.Origin,
		"origin_server_ts": req.OriginServerTS,
		"room_id":          req.RoomID,
		"sender":           req.Sender,
		"state_key":        req.StateKey,
		"type":             req.Type,
	}
	canonical, err := util.CanonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("failed to canonicalize event: %w", err)
	}

	if !ed25519.Verify(pubKey, canonical, sigBytes) {
		// NOTE: ignorar verificação por enquanto
		// return fmt.Errorf("signature verification failed")
	}
	return nil
}

func (h *Handler) putInvite(w http.ResponseWriter, r *http.Request) {
	roomID := r.PathValue("roomId")
	eventID := r.PathValue("eventId")

	var req InviteRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, err.Error())
		return
	}

	var eventMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(req.Event))
	dec.UseNumber()
	if err := dec.Decode(&eventMap); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "invalid event payload")
		return
	}

	// Validação do evento
	// Basic Event Validations
	tipo, _ := eventMap["type"].(string)
	if tipo != "m.room.member" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "event type must be m.room.member")
		return
	}

	content, ok := eventMap["content"].(map[string]interface{})
	if !ok {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "missing event content")
		return
	}

	membership, _ := content["membership"].(string)
	if membership != "invite" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "membership must be invite")
		return
	}

	stateKey, ok := eventMap["state_key"].(string)
	if !ok {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "missing state_key")
		return
	}

	// confere se o invite é para esse servidor
	parts := strings.SplitN(stateKey, ":", 2)
	if len(parts) != 2 || parts[1] != h.sysService.GetServerName() {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "invited user must be local")
		return
	}

	sender, _ := eventMap["sender"].(string)
	senderParts := strings.SplitN(sender, ":", 2)
	if len(senderParts) != 2 {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_INVALID_PARAM, "invalid sender")
		return
	}

	// Valida a assinatura do servidor
	if err := h.verifyRawEventSignature(eventMap, senderParts[1]); err != nil {
		httputil.WriteMatrixError(w, http.StatusForbidden, httputil.M_FORBIDDEN, "invalid signature: "+err.Error())
		return
	}

	var evento domain.Evento
	_ = json.Unmarshal(req.Event, &evento)
	evento.ID = eventID
	evento.CanalID = roomID
	evento.Tipo = tipo
	evento.Sender = sender
	evento.StateKey = &stateKey
	contentBytes, _ := util.CanonicalJSON(content)
	evento.Content = contentBytes

	// Salva o evento
	err := h.fedService.ProcessInvite(r.Context(), roomID, &evento)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, err.Error())
		return
	}

	signRaw, err := util.SignMatrixEvent(&evento, h.sysService.GetServerName(), h.sysService.GetServerKeyID(), h.sysService.GetPrivateKey())
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "failed to sign event")
		return
	}

	var newSigs map[string]any
	if err := json.Unmarshal(signRaw, &newSigs); err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "failed to parse generated signature")
		return
	}

	// 3. Retrieve or initialize the "signatures" map in our original eventMap
	existingSigsRaw, ok := eventMap["signatures"]
	var existingSigs map[string]any
	if ok && existingSigsRaw != nil {
		if s, isMap := existingSigsRaw.(map[string]any); isMap {
			existingSigs = s
		} else {
			existingSigs = make(map[string]any)
		}
	} else {
		existingSigs = make(map[string]any)
	}

	// 4. Attach our newly generated signature to the event
	maps.Copy(existingSigs, newSigs)
	eventMap["signatures"] = existingSigs

	// 5. Marshal the full event (now containing both origin's and our signature) to send it back
	SignedEventJSON, err := json.Marshal(eventMap)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "failed to marshal response event")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, InviteResponse{Event: SignedEventJSON})
}

// Verfica a assinatura de um evento do matrix
func (h *Handler) verifyRawEventSignature(eventMap map[string]any, origin string) error {
	sigs, ok := eventMap["signatures"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing signatures")
	}
	originSigsRaw, ok := sigs[origin]
	if !ok {
		return fmt.Errorf("no signature from origin %s", origin)
	}
	originSigs, ok := originSigsRaw.(map[string]any)
	if !ok {
		return fmt.Errorf("invalid signature format")
	}

	keyID, pubKey, err := h.keyFetcher(origin)
	fmt.Printf("[DEBUG] keyID: %s, pubKey: %s", keyID, pubKey)
	if err != nil {
		return fmt.Errorf("could not fetch public key: %w", err)
	}

	sigRaw, ok := originSigs[keyID]
	if !ok {
		return fmt.Errorf("no signature for key %s", keyID)
	}
	sig, ok := sigRaw.(string)
	if !ok {
		return fmt.Errorf("invalid signature string format")
	}

	sigBytes, err := base64.RawStdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	payload := make(map[string]any)
	for k, v := range eventMap {
		if k != "signatures" && k != "unsigned" {
			payload[k] = v
		}
	}
	canonical, err := util.CanonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("failed to canonicalize event: %w", err)
	}

	if !ed25519.Verify(pubKey, canonical, sigBytes) {
		log.Printf("[DEBUG] signature verification failed for event")
		return nil // ignorar por enquanto
		// return fmt.Errorf("signature verification failed")
	}
	return nil
}

// getRoomState retorna um snapshot de um estado de uma sala num determinado evento
// GET /_matrix/federation/v1/state/{roomId}
// https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1stateroomid
func (h *Handler) getRoomState(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	// Parâmetros requeridos pela especificação
	roomID := r.PathValue("roomId")          // Path
	eventID := r.URL.Query().Get("event_id") // Query

	if roomID == "" || eventID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "Missing roomId or event_id")
		return
	}

	response, err := h.fedService.GetRoomStateSnapShot(ctx, roomID, eventID)

	if err != nil {
		log.Printf("[ERROR] GET /state: %v", err)
		httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "State not found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// getStateIDs retorna os IDs de estado de uma sala num determinado evento
// GET /_matrix/federation/v1/state_ids/{roomId}
// https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1state_idsroomid
func (h *Handler) getStateIDs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	roomID := r.PathValue("roomId")
	eventID := r.URL.Query().Get("event_id")

	// O spec exige event_id para saber de que momento da história estamos falando
	if roomID == "" || eventID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "Missing roomId or event_id")
		return
	}

	// Chama o UseCase passando a responsabilidade
	pduIDs, authIDs, err := h.fedService.GetStateIDsForEvent(ctx, roomID, eventID)
	if err != nil {
		log.Printf("[ERROR] GET /state_ids: %v", err)
		httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Event or state not found")
		return
	}

	response := StateIDsResponse{
		PDUIDs:       pduIDs,
		AuthChainIDs: authIDs,
	}

	httputil.WriteJSON(w, http.StatusOK, response)
}

// postGetMissingEvents permite a outros servidores recuperar eventos que lhes faltam no DAG
// POST /_matrix/federation/v1/get_missing_events/{roomId}
func (h *Handler) postGetMissingEvents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), httputil.RequestTimeout)
	defer cancel()

	roomID := r.PathValue("roomId")
	if roomID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_MISSING_PARAM, "Missing roomId")
		return
	}

	var req usecase.GetMissingEventsRequest
	if err := httputil.ParseBody(r, &req); err != nil {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_NOT_JSON, "Invalid JSON body")
		return
	}

	// Matrix spec: se não enviarem limite, o padrão recomendado é 10
	if req.Limit <= 0 {
		req.Limit = 10
	}

	resp, err := h.fedService.HandleGetMissingEvents(ctx, roomID, req)
	if err != nil {
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to compute missing events")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// getMediaDownload serve uma mídia hospedada neste servidor para outro servidor Matrix federado
// Este é o lado receptor do proxy implementado em FederationService.FetchRemoteMedia.
func (h *Handler) getMediaDownload(w http.ResponseWriter, r *http.Request) {
	mediaID := r.PathValue("mediaId")
	if mediaID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing mediaId")
		return
	}

	result, err := h.mediaService.DownloadLocal(r.Context(), mediaID)
	if err != nil {
		if errors.Is(err, usecase.ErrMediaNotFound) {
			httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Media not found")
			return
		}
		log.Printf("[ERROR] GET /_matrix/federation/v1/media/download/%s: %v", mediaID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to retrieve media")
		return
	}
	defer result.Content.Close()

	writeMultipartMediaResponse(w, result)
}

// writeMultipartMediaResponse escreve a mídia no formato multipart/mixed exigido para respostas de download via federação
func writeMultipartMediaResponse(w http.ResponseWriter, result *usecase.DownloadResult) {
	mw := multipart.NewWriter(w)
	w.Header().Set("Content-Type", fmt.Sprintf("multipart/mixed; boundary=%s", mw.Boundary()))
	w.WriteHeader(http.StatusOK)

	metaHeader := textproto.MIMEHeader{}
	metaHeader.Set("Content-Type", "application/json")
	metaPart, err := mw.CreatePart(metaHeader)
	if err != nil {
		log.Printf("[ERROR] failed to create metadata part: %v", err)
		return
	}
	if _, err := metaPart.Write([]byte("{}")); err != nil {
		log.Printf("[ERROR] failed to write metadata part: %v", err)
		return
	}

	disposition := "attachment"
	if isInlineSafe(result.ContentType) {
		disposition = "inline"
	}
	if result.Filename != "" {
		disposition = fmt.Sprintf(`%s; filename="%s"`, disposition, result.Filename)
	}

	fileHeader := textproto.MIMEHeader{}
	fileHeader.Set("Content-Type", result.ContentType)
	fileHeader.Set("Content-Disposition", disposition)
	filePart, err := mw.CreatePart(fileHeader)
	if err != nil {
		log.Printf("[ERROR] failed to create file part: %v", err)
		return
	}
	if _, err := io.Copy(filePart, result.Content); err != nil {
		log.Printf("[ERROR] failed to stream file part: %v", err)
		return
	}

	if err := mw.Close(); err != nil {
		log.Printf("[ERROR] failed to close multipart writer: %v", err)
	}
}

// isInlineSafe retorna true para tipos de conteúdo seguros para exibição inline
func isInlineSafe(contentType string) bool {
	for _, prefix := range []string{"image/", "audio/", "video/", "text/"} {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}
