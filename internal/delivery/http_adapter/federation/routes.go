package federation

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/usecase"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type Handler struct {
	sysService             *usecase.SystemService
	fedService             *usecase.FederationService
	roomInteractionService *usecase.RoomInteractionService
}

func NewHandler(sysService *usecase.SystemService, fedService *usecase.FederationService, roomInteractionService *usecase.RoomInteractionService) *Handler {
	return &Handler{
		sysService:             sysService,
		fedService:             fedService,
		roomInteractionService: roomInteractionService,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /_matrix/federation/v1/version", h.getVersion)
	mux.HandleFunc("GET /_matrix/key/v2/server", h.getServerKey)

	// TODO: include authentication for all this endpoints
	// receive transactions
	mux.HandleFunc("PUT /_matrix/federation/v1/send/{txnId}", h.putSendTxn)

	// retrieve missing events
	mux.HandleFunc("GET /_matrix/federation/v1/backfill/{roomId}", h.getBackfill)
	mux.HandleFunc("GET /_matrix/federation/v1/event/{eventId}", h.getEvent)
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

func (h *Handler) putSendTxn(w http.ResponseWriter, r *http.Request) {
	txnID := r.PathValue("txnId")
	if txnID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing txn ID")
		return
	}

	// TODO: validar o S2S, ler o X-Matrix, buscar a chave publica e autenticar

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
