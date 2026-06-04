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

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/repository"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type Handler struct {
	config *types.ServerConfig
	userStore repository.UserStore
	canalStore repository.ChannelStore
}

func NewHandler(config *types.ServerConfig, userStore repository.UserStore, canalStore repository.ChannelStore) *Handler {
	return &Handler{config: config, userStore: userStore, canalStore: canalStore}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /_matrix/federation/v1/version", h.getVersion)
	mux.HandleFunc("GET /_matrix/key/v2/server", h.getServerKey)
	mux.HandleFunc("GET /_matrix/federation/v1/query/profile", h.getProfile)
	mux.HandleFunc("GET /_matrix/federation/v1/publicRooms", h.getPublicRooms)
    mux.HandleFunc("POST /_matrix/federation/v1/publicRooms", h.postPublicRooms)
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