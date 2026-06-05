package federation

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"
	"strings"
	"net/http"
	"strconv"
	"encoding/json"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/repository"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

// keyFetcherFn permite injetar a busca de chave remota nos testes.
type keyFetcherFn func(serverName string) (string, ed25519.PublicKey, error)

type Handler struct {
	config       		*types.ServerConfig
	userStore 			repository.UserStore
	canalStore 			repository.ChannelStore
	eventoStore       	repository.EventoStore
    usuarioCanalStore 	repository.UsuarioCanalStore
	keyFetcher          keyFetcherFn
}

func NewHandler(config *types.ServerConfig, userStore repository.UserStore, canalStore repository.ChannelStore, 
	eventoStore repository.EventoStore, usuarioCanalStore repository.UsuarioCanalStore) *Handler {
	return &Handler{config: config, userStore: userStore, canalStore: canalStore, eventoStore: eventoStore, usuarioCanalStore: usuarioCanalStore,
		keyFetcher: util.FetchRemoteServerKey}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /_matrix/federation/v1/version", h.getVersion)
	mux.HandleFunc("GET /_matrix/key/v2/server", h.getServerKey)
	mux.HandleFunc("GET /_matrix/federation/v1/query/profile", h.getProfile)
	mux.HandleFunc("GET /_matrix/federation/v1/publicRooms", h.getPublicRooms)
    mux.HandleFunc("POST /_matrix/federation/v1/publicRooms", h.postPublicRooms)
	mux.HandleFunc("GET /_matrix/federation/v1/make_join/{roomId}/{userId}", h.makeJoin)
    mux.HandleFunc("PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}", h.sendJoin)
}

func (h *Handler) getVersion(w http.ResponseWriter, r *http.Request) {
	res := VersionResponse{}
	res.Server.Name = h.config.ServerName
	res.Server.Version = h.config.Version
	util.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) getServerKey(w http.ResponseWriter, r *http.Request) {
	resp := ServerKeyResponse{}

	resp.ServerName = h.config.ServerName
	// Validade de 1 ano
	resp.ValidUntilTS = time.Now().Add(365 * 24 * time.Hour).UnixMilli()
	publicKey := base64.RawStdEncoding.EncodeToString(h.config.PublicKey)
	resp.VerifyKeys = map[string]VerifyKey{
		h.config.KeyID: {
			Key: publicKey,
		},
	}

	// Criptografia
	canonicalJson, err := util.CanonicalJSON(resp)
	if err != nil {
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_BAD_JSON, err.Error()))
		return
	}
	signatureBytes := ed25519.Sign(h.config.PrivateKey, canonicalJson)
	signatureBase64 := base64.RawStdEncoding.EncodeToString(signatureBytes)

	// add signature
	resp.Signatures = map[string]map[string]string{
		h.config.ServerName: {
			h.config.KeyID: signatureBase64,
		},
	}

	util.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) getProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_MISSING_PARAM, "user_id is required"))
		return
	}

	// Homeservers devem apenas responder por usuários locais.
	// O server name fica após o ":" no Matrix user ID (@localpart:server_name).
	parts := strings.SplitN(userID, ":", 2)
	if len(parts) != 2 || parts[1] != h.config.ServerName {
		util.WriteError(w, http.StatusNotFound, types.NewErrorResponse(types.M_NOT_FOUND, "User does not exist."))
		return
	}

	field := r.URL.Query().Get("field")
	if field != "" && field != "displayname" && field != "avatar_url" {
		util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_INVALID_PARAM, "field must be 'displayname' or 'avatar_url'"))
		return
	}

	usuario, err := h.userStore.GetNameAndPhotoByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			util.WriteError(w, http.StatusNotFound, types.NewErrorResponse(types.M_NOT_FOUND, "User does not exist."))
			return
		}
		util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, err.Error()))
		return
	}

	res := model.ProfileResponse{
		DisplayName: usuario.Nome,
		AvatarURL:   usuario.Foto,
	}

	// Se um field específico foi pedido, zeramos o outro.
	// Os tags omitempty no ProfileResponse garantem que campos vazios não apareçam no JSON
	switch field {
	case "displayname":
		res.AvatarURL = ""
	case "avatar_url":
		res.DisplayName = ""
	}

	util.WriteJSON(w, http.StatusOK, res)
}

// canalToChunk converte um Canal para o formato PublishedRoomsChunk da spec Matrix.
// guest_can_join e world_readable são derivados dos campos de estado da sala.
func canalToChunk(c model.Canal) PublishedRoomsChunk {
    chunk := PublishedRoomsChunk{
        RoomID:           c.ID,
        NumJoinedMembers: c.MemberCount,
        GuestCanJoin:     c.GuestAccess == "can_join",
        WorldReadable:    c.HistoryVisibility == "world_readable",
        Name:             c.Nome,
        Topic:            c.Descricao,
        AvatarURL:        c.Foto,
        JoinRule:         c.JoinRules,
    }
    if c.CanonAlias != nil {
        chunk.CanonicalAlias = *c.CanonAlias
    }
    if c.RoomType != nil {
        chunk.RoomType = *c.RoomType
    }
    return chunk
}

func (h *Handler) getPublicRooms(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()

    limit := 0
    if s := q.Get("limit"); s != "" {
        if v, err := strconv.Atoi(s); err == nil {
            limit = v
        }
    }

    params := repository.ListPublicParams{
        Limit:      limit,
        SinceToken: q.Get("since"),
    }

    h.writePublicRooms(w, r, params)
}

func (h *Handler) postPublicRooms(w http.ResponseWriter, r *http.Request) {
    var req PublicRoomsRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_BAD_JSON, err.Error()))
        return
    }

    params := repository.ListPublicParams{
        Limit:      req.Limit,
        SinceToken: req.Since,
    }
    if req.Filter != nil {
        params.SearchTerm = req.Filter.GenericSearchTerm
        params.RoomTypes = req.Filter.RoomTypes
    }

    h.writePublicRooms(w, r, params)
}

// writePublicRooms executa a busca e escreve a resposta, compartilhado entre GET e POST
func (h *Handler) writePublicRooms(w http.ResponseWriter, r *http.Request, params repository.ListPublicParams) {
    canais, nextBatch, prevBatch, total, err := h.canalStore.ListPublic(r.Context(), params)
    if err != nil {
        util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, err.Error()))
        return
    }

    chunks := make([]PublishedRoomsChunk, 0, len(canais))
    for _, c := range canais {
        chunks = append(chunks, canalToChunk(c))
    }

    resp := PublicRoomsResponse{
        Chunk:                  chunks,
        NextBatch:              nextBatch,
        PrevBatch:              prevBatch,
        TotalRoomCountEstimate: &total,
    }
    util.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) makeJoin(w http.ResponseWriter, r *http.Request) {
    roomID := r.PathValue("roomId")
    userID := r.PathValue("userId")

    // verifica se a sala existe
    canal, err := h.canalStore.GetByID(r.Context(), roomID)
    if err != nil {
        if errors.Is(err, types.ErrNotFound) {
            util.WriteError(w, http.StatusNotFound, types.NewErrorResponse(types.M_NOT_FOUND, "Unknown room"))
            return
        }
        util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, err.Error()))
        return
    }

    // verifica compatibilidade de versão da sala.
    // o parâmetro `ver` é uma lista de versões suportadas pelo servidor remoto, se não informado, assume ["1"].
    supportedVers := r.URL.Query()["ver"]
    if len(supportedVers) == 0 {
        supportedVers = []string{"1"}
    }
    roomVersion := canal.Versao
    versionSupported := false
    for _, v := range supportedVers {
        if v == roomVersion {
            versionSupported = true
            break
        }
    }
    if !versionSupported {
        util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(
            types.M_INCOMPATIBLE_ROOM_VERSION,
            "Your homeserver does not support the features required to join this room",
        ))
        return
    }

    // verifica se a sala permite entrada pública
    if canal.JoinRules != "public" {
        util.WriteError(w, http.StatusForbidden, types.NewErrorResponse(types.M_FORBIDDEN, "You are not invited to this room"))
        return
    }

    resp := MakeJoinResponse{
        RoomVersion: roomVersion,
        Event: EventTemplate{
            Type:           "m.room.member",
            Sender:         userID,
            StateKey:       userID,
            RoomID:         roomID,
            Origin:         h.config.ServerName,
            OriginServerTS: time.Now().UnixMilli(),
            Content: MembershipContent{
                Membership: "join",
            },
        },
    }

    util.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handler) sendJoin(w http.ResponseWriter, r *http.Request) {
    roomID := r.PathValue("roomId")

    // Verifica se a sala existe
    if _, err := h.canalStore.GetByID(r.Context(), roomID); err != nil {
        if errors.Is(err, types.ErrNotFound) {
            util.WriteError(w, http.StatusNotFound, types.NewErrorResponse(types.M_NOT_FOUND, "Unknown room"))
            return
        }
        util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, err.Error()))
        return
    }

    var req SendJoinRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_BAD_JSON, err.Error()))
        return
    }

    // Validações obrigatórias pela spec
    if req.Type != "m.room.member" {
        util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_INVALID_PARAM, "event type must be m.room.member"))
        return
    }
    if req.Content.Membership != "join" {
        util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_INVALID_PARAM, "membership must be join"))
        return
    }
    if req.Sender != req.StateKey {
        util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_INVALID_PARAM, "sender must equal state_key"))
        return
    }

    // Verifica que o sender pertence ao servidor de origem
    senderParts := strings.SplitN(req.Sender, ":", 2)
    if len(senderParts) != 2 || senderParts[1] != req.Origin {
        util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_INVALID_PARAM, "sender must belong to the origin server"))
        return
    }

    // Busca e verifica a assinatura ed25519 do servidor de origem
    if err := h.verifyEventSignature(req); err != nil {
        util.WriteError(w, http.StatusBadRequest, types.NewErrorResponse(types.M_INVALID_PARAM, "invalid event signature: "+err.Error()))
        return
    }

    // Persiste o evento de membro
    eventoID := req.EventID
    if eventoID == "" {
        eventoID = "$" + req.Sender + ":" + req.Origin
    }
    evento := &model.Evento{
        ID:               eventoID,
        Tipo:             req.Type,
        CanalID:          roomID,
        SenderID:         req.Sender,
        StateKey:         req.StateKey,
        Conteudo:         `{"membership":"join"}`,
        OrigemServidorTS: req.OriginServerTS,
    }
    if err := h.eventoStore.Create(r.Context(), evento); err != nil {
        util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, err.Error()))
        return
    }

    // Atualiza a membresia do usuário na sala
    membro := &model.UsuarioCanal{
        CanalID:   roomID,
        UsuarioID: req.Sender,
        Membresia: "join",
        JoinedAt:  time.Now(),
    }
    if err := h.usuarioCanalStore.AddOrUpdateMembership(r.Context(), membro); err != nil {
        util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, err.Error()))
        return
    }

    // Atualiza o estado atual da sala
    estadoMembro := &model.EstadoAtualCanal{
        CanalID:  roomID,
        Tipo:     "m.room.member",
        StateKey: req.Sender,
        EventoID: eventoID,
    }
    if err := h.canalStore.UpsertEstadoAtual(r.Context(), estadoMembro); err != nil {
        util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, err.Error()))
        return
    }

	// Incrementa o contador de membros da sala
	if err := h.canalStore.UpdateMemberCount(r.Context(), roomID, 1); err != nil {
    // não fatal, imprime no console mas não falha o join
    fmt.Printf("[WARN] sendJoin: failed to update member count for %s: %v\n", roomID, err)
	}

    // Busca o estado atual para incluir na resposta
    stateEventos, err := h.eventoStore.GetCurrentStateEvents(r.Context(), roomID)
    if err != nil {
        util.WriteError(w, http.StatusInternalServerError, types.NewErrorResponse(types.M_UNKNOWN, err.Error()))
        return
    }

    statePDUs := eventosToPDUs(stateEventos)

    // Servidores ativos na sala (para servers_in_room)
    userIDs, _ := h.usuarioCanalStore.GetJoinedUserIDsInRoom(r.Context(), roomID)
    servers := extractServers(userIDs)

    resp := SendJoinResponse{
        State:     statePDUs,
        AuthChain: statePDUs, // simplificação: auth chain = estado atual
    }
    if len(servers) > 0 {
        resp.ServersInRoom = servers
    }

    util.WriteJSON(w, http.StatusOK, resp)
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

    // Reconstrói o payload sem signatures e unsigned para verificar
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

// eventosToPDUs converte eventos internos para o formato StatePDU da spec.
func eventosToPDUs(eventos []model.Evento) []StatePDU {
    pdus := make([]StatePDU, 0, len(eventos))
    for _, e := range eventos {
        pdus = append(pdus, StatePDU{
            EventID:        e.ID,
            Type:           e.Tipo,
            RoomID:         e.CanalID,
            Sender:         e.SenderID,
            StateKey:       e.StateKey,
            OriginServerTS: e.OrigemServidorTS,
            Content:        json.RawMessage(e.Conteudo),
        })
    }
    return pdus
}

// extractServers extrai os server names únicos a partir de uma lista de user IDs.
func extractServers(userIDs []string) []string {
    seen := make(map[string]bool)
    servers := make([]string, 0)
    for _, uid := range userIDs {
        parts := strings.SplitN(uid, ":", 2)
        if len(parts) == 2 && !seen[parts[1]] {
            seen[parts[1]] = true
            servers = append(servers, parts[1])
        }
    }
    return servers
}