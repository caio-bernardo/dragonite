package usecase

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

// buildFederationURL monta a URL final de uma chamada S2S de forma consistente,
// evitando "http://" e "https://" hardcoded espalhados pelo arquivo. O esquema vem de
// util.FederationScheme, fonte única também usada por util.FetchRemoteServerKey, pra
// não ter dois lugares pra lembrar de trocar quando TLS entrar em produção.
func buildFederationURL(targetHost, uri string) string {
	return fmt.Sprintf("%s://%s%s", util.FederationScheme, targetHost, uri)
}

type GetMissingEventsRequest struct {
	EarliestEvents []string `json:"earliest_events"`
	LatestEvents   []string `json:"latest_events"`
	Limit          int      `json:"limit"`
	MinDepth       int64    `json:"min_depth"`
}

type GetMissingEventsResponse struct {
	Events []domain.Evento `json:"events"`
}

type RoomStateResponse struct {
	AuthChain []domain.Evento `json:"auth_chain"`
	PDUs      []domain.Evento `json:"pdus"`
}

type BackfillResult struct {
	Origin         string          `json:"origin"`
	OriginServerTS int64           `json:"origin_server_ts"`
	PDUs           []domain.Evento `json:"pdus"`
}

type StateResolver interface {
	Resolve(ctx context.Context, input domain.StateResolutionInput) (domain.StateMap, error)
}

type FederationService struct {
	// TODO: trocar esse channel por uma fila apropria. Mas por enquanto mantém
	outboundQueue    chan domain.Evento
	serverName       string
	keyID            string
	privateKey       ed25519.PrivateKey
	canalStore       CanalStorage
	eventoStore      EventoStorage
	uow              WorkUnit
	authRuleResolver *AuthRuleResolver
	stateResolver    StateResolver
}

func NewFederationService(serverName, keyID string, privateKey ed25519.PrivateKey, canalStore CanalStorage, eventoStore EventoStorage, uow WorkUnit, authRuleResolver *AuthRuleResolver, stateResolver StateResolver) *FederationService {
	fs := &FederationService{
		outboundQueue:    make(chan domain.Evento, 1000),
		serverName:       serverName,
		keyID:            keyID,
		privateKey:       privateKey,
		canalStore:       canalStore,
		eventoStore:      eventoStore,
		uow:              uow,
		authRuleResolver: authRuleResolver,
		stateResolver:    stateResolver,
	}

	// nova thread que vai rodar o worker
	go fs.startWorker()

	return fs
}

func (f *FederationService) QueueOutgoing(ctx context.Context, event domain.Evento) error {
	select {
	case f.outboundQueue <- event:
		return nil
	default:
		return types.InternalError(errors.New("Queue is full!"))
	}
}

func (f *FederationService) startWorker() {
	log.Println("[Federation] Background Worker just started")

	for event := range f.outboundQueue {
		destinations := f.extractDestionations(event)

		for _, dest := range destinations {
			if dest == f.serverName {
				continue
			}
			go f.sendWithRetry(dest, event)
		}
	}
}

func (f *FederationService) sendWithRetry(dest string, event domain.Evento) {
	targetHost, err := util.ResolveServerName(dest)
	if err != nil {
		log.Printf("[Federation] Failed to resolve server name %s: %v", dest, err)
		return
	}

	// Backoff exponencial
	maxRetries := 5 // Num servidor de verdade deveria ser 16 ou 17 retries
	for i := range maxRetries {
		err := f.sendTransaction(targetHost, dest, event)
		if err == nil {
			return
		}
		log.Printf("[Federation] Retry %d/%d failed: %v", i+1, maxRetries, err)
		// fazemos a requisição de novo em 2^i segundos
		time.Sleep(time.Duration(2<<i) * time.Second)
	}
}

func (f *FederationService) sendTransaction(targetHost, dest string, event domain.Evento) error {
	txnID := fmt.Sprintf("%d", time.Now().UnixMilli())

	uri := fmt.Sprintf("/_matrix/federation/v1/send/%s", txnID)

	txnPayload := map[string]any{
		"origin":           f.serverName,
		"origin_server_ts": event.OrigemServidorTS,
		"pdus":             []domain.Evento{event},
	}
	txnBytes, err := util.CanonicalJSON(txnPayload)
	if err != nil {
		return fmt.Errorf("failed to canonicalize txn payload: %w", err)
	}

	authHeader, err := util.GenerateS2SAuthHeader(f.serverName, f.keyID,
		f.privateKey, "PUT", uri, dest, txnPayload)
	if err != nil {
		return fmt.Errorf("failed to generate auth header: %w", err)
	}

	reqURL := buildFederationURL(targetHost, uri)
	req, err := http.NewRequest("PUT", reqURL, bytes.NewBuffer(txnBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func (f *FederationService) extractDestionations(event domain.Evento) []string {
	destinations := make(map[string]bool)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. pega todos servidores dos membros ativos (invite + join)
	servers, err := f.canalStore.GetCanalParticipatingServers(ctx, event.CanalID)
	if err == nil {
		for _, srv := range servers {
			destinations[srv] = true
		}
	}

	// 2. Adiciona servidores de alvos de eventos (invite, kick, leave, etc)
	if event.Tipo == "m.room.member" && event.StateKey != nil {
		var content map[string]any
		if err := json.Unmarshal(event.Content, &content); err == nil {
			if membership, ok := content["membership"].(string); ok {
				// Se é um convite, ou uma ação coercitiva/saída, o servidor do alvo deve saber
				if membership == "invite" || membership == "leave" || membership == "ban" || membership == "knock" {
					targetDomain := util.ExtractDomainFromUserID(*event.StateKey)
					if targetDomain != "" {
						destinations[targetDomain] = true
					}
				}
			}
		}
	}
	// Conversão do mapa para um Slice final, REMOVENDO o próprio servidor (não federamos pra nós mesmos)
	var finalDestinations []string
	for dom := range destinations {
		if dom != "" && dom != f.serverName {
			finalDestinations = append(finalDestinations, dom)
		}
	}

	return finalDestinations
}

func (f *FederationService) ProcessInboundPDU(ctx context.Context, origin string, pdu domain.Evento) error {
	// verificação básica do evento
	expectedID, err := util.HashMatrixEvent(&pdu)
	if err != nil || pdu.ID != expectedID {
		return fmt.Errorf("evento com ID incorreto: esperado %s, encontrado %s", expectedID, pdu.ID)
	}

	// TODO: verificar a assinatura do evento, remover signatures e verificar a chave pública do servidor

	// Resolver extremidades e falta de histórico
	missingPrevs, err := f.checkMissingEvents(ctx, pdu.PrevEventos)
	if err != nil {
		return fmt.Errorf("falha ao resolver extremidades: %w", err)
	}

	if len(missingPrevs) > 0 {

		historicalEvents, err := f.fetchMissingEvents(ctx, origin, pdu.CanalID, missingPrevs)
		if err != nil {
			return err
		}

		for _, histPDU := range historicalEvents {

			histID, _ := util.HashMatrixEvent(&histPDU)

			// Compatibilidade com o matrix v3
			if histPDU.ID == "" {
				histPDU.ID = histID
			}

			if histID == histPDU.ID {
				_ = f.uow.Execute(ctx, func(txCtx context.Context) error {
					err = f.eventoStore.SaveEvento(txCtx, &histPDU)
					if err != nil {
						return err
					}
					err = f.canalStore.UpdateForwardExtremities(txCtx, histPDU.CanalID, histPDU.ID, histPDU.PrevEventos)
					if err != nil {
						return err
					}

					err = f.updateRoomStateAndMembership(txCtx, &histPDU)
					if err != nil {
						return err
					}
					return nil
				})
			}
		}
	}

	// State Res Algo. Resolve o estado do canal no ponto em que o novo evento se conecta ao grafo.
	resolvedStateBefore, err := f.resolveStateAtIngestion(ctx, pdu.CanalID, pdu.PrevEventos)
	if err != nil {
		return fmt.Errorf("falha no consenso do estado (State Res v2): %w", err)
	}

	// Verificar as regras do Grafo
	_, _, err = f.authRuleResolver.ResolveEventDependencies(ctx, pdu.CanalID, pdu.Sender, pdu.Tipo, pdu.StateKey)
	if err != nil {
		return fmt.Errorf("falha ao resolver dependências: %w", err)
	}

	// Se o novo evento é um evento de estado, atualizamos o mapa
	resolvedStateAfter := make(domain.StateMap)
	maps.Copy(resolvedStateAfter, resolvedStateBefore)

	if pdu.StateKey != nil {
		newTuple := domain.NewStateTuple(pdu.Tipo, pdu.StateKey)
		resolvedStateAfter[newTuple] = pdu.ID
	}

	// Inserir de modo seguro no DAG
	err = f.uow.Execute(ctx, func(txCtx context.Context) error {
		if err := f.eventoStore.SaveEvento(txCtx, &pdu); err != nil {
			return fmt.Errorf("falha ao salvar evento: %w", err)
		}

		// atualiza extremidades
		if err := f.canalStore.UpdateForwardExtremities(txCtx, pdu.CanalID, pdu.ID, pdu.PrevEventos); err != nil {
			return fmt.Errorf("falha ao atualizar extremidades: %w", err)
		}

		// atualiza estado da sala se necessário
		if err := f.updateRoomStateAndMembership(txCtx, &pdu); err != nil {
			return fmt.Errorf("falha ao atualizar estado da sala: %w", err)
		}

		return nil
	})

	return err
}

func (f *FederationService) checkMissingEvents(ctx context.Context, prevEvents []string) ([]string, error) {
	var missing []string
	for _, id := range prevEvents {
		// Verifique no seu eventoRepo se o evento existe
		exists, err := f.eventoStore.CheckEventoExists(ctx, id)
		if err != nil {
			return nil, err
		}
		if !exists {
			missing = append(missing, id)
		}
	}
	return missing, nil
}

func (f *FederationService) fetchMissingEvents(ctx context.Context, originServer, roomID string, missingPrev []string) ([]domain.Evento, error) {
	targetHost, err := util.ResolveServerName(originServer)
	if err != nil {
		return nil, err
	}

	uri := fmt.Sprintf("/_matrix/federation/v1/get_missing_events/%s", roomID)

	knownExtremities, _ := f.canalStore.GetForwardExtremities(ctx, roomID)
	if knownExtremities == nil {
		knownExtremities = []string{}
	}
	payload := GetMissingEventsRequest{
		EarliestEvents: knownExtremities,
		LatestEvents:   missingPrev,
		Limit:          10, // busca até 10 eventos no passado
		MinDepth:       0,
	}

	payloadBytes, _ := util.CanonicalJSON(payload)

	// Assinamos a requisição (X-Matrix) porque é S2S
	authHeader, err := util.GenerateS2SAuthHeader(
		f.serverName, f.keyID, f.privateKey,
		"POST", uri, originServer, payload,
	)
	if err != nil {
		return nil, fmt.Errorf("falha ao assinar requisição de backfill: %w", err)
	}

	reqURL := buildFederationURL(targetHost, uri)
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("servidor remoto rejeitou get_missing_events com status %d", resp.StatusCode)
	}

	var response GetMissingEventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("falha ao decodificar a resposta de missing events: %w", err)
	}

	return response.Events, nil
}

// ErrIncompatibleRoomVersion é retornado quando o servidor remoto não suporta a versão da sala.
var ErrIncompatibleRoomVersion = errors.New("incompatible room version")

type MakeJoinResult struct {
	RoomVersion string
	Sender      string
	RoomID      string
	Origin      string
	Timestamp   int64
}

func (f *FederationService) MakeJoin(ctx context.Context, roomID, userID string, supportedVersions []string) (*MakeJoinResult, error) {
	canal, err := f.canalStore.GetByID(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up room: %w", err)
	}
	if canal == nil {
		return nil, types.ErrNotFound
	}

	// Verifica compatibilidade de versão
	versionOK := slices.Contains(supportedVersions, canal.Versao)
	if !versionOK {
		return nil, ErrIncompatibleRoomVersion
	}

	// Verifica se a sala permite entrada pública
	joinRule, err := f.canalStore.GetJoinRule(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to get join rule: %w", err)
	}

	if joinRule == "invite" {
		membership, err := f.canalStore.GetUserMembership(ctx, roomID, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to get user membership: %w", err)
		}
		if membership != "invite" {
			return nil, types.ErrForbidden
		}
	} else if joinRule != "public" {
		return nil, types.ErrForbidden
	}

	return &MakeJoinResult{
		RoomVersion: canal.Versao,
		Sender:      userID,
		RoomID:      roomID,
		Origin:      f.serverName,
		Timestamp:   time.Now().UnixMilli(),
	}, nil
}

type SendJoinResult struct {
	StateEvents   []domain.Evento
	ServersInRoom []string
}

func (f *FederationService) ProcessSendJoin(ctx context.Context, roomID string, joinEvent *domain.Evento) (*SendJoinResult, error) {
	// Verifica se a sala existe
	canal, err := f.canalStore.GetByID(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to check room: %w", err)
	}
	if canal == nil {
		return nil, types.ErrNotFound
	}

	// Persiste o evento de join e atualiza o estado
	err = f.uow.Execute(ctx, func(txCtx context.Context) error {
		if err := f.eventoStore.SaveEvento(txCtx, joinEvent); err != nil {
			return fmt.Errorf("failed to save join event: %w", err)
		}
		if err := f.canalStore.UpsertCurrentState(txCtx, roomID, "m.room.member", joinEvent.Sender, joinEvent.ID); err != nil {
			return fmt.Errorf("failed to upsert current state: %w", err)
		}
		if err := f.canalStore.UpsertMembership(txCtx, roomID, joinEvent.Sender, "join", joinEvent.ID); err != nil {
			return fmt.Errorf("failed to upsert membership: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Busca o estado atual da sala para a resposta
	stateEvents, err := f.eventoStore.GetCurrentStateEvents(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current state: %w", err)
	}
	if stateEvents == nil {
		stateEvents = []domain.Evento{}
	}

	// Servidores ativos na sala
	servers, err := f.canalStore.GetCanalParticipatingServers(ctx, roomID)
	if err != nil {
		servers = []string{}
	}

	return &SendJoinResult{
		StateEvents:   stateEvents,
		ServersInRoom: servers,
	}, nil
}

type MakeLeaveResult struct {
	RoomVersion string
	Sender      string
	RoomID      string
	Origin      string
	Timestamp   int64
}

func (f *FederationService) MakeLeave(ctx context.Context, roomID, userID string) (*MakeLeaveResult, error) {
	canal, err := f.canalStore.GetByID(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up room: %w", err)
	}
	if canal == nil {
		return nil, types.ErrNotFound
	}

	membership, err := f.canalStore.GetUserMembership(ctx, roomID, userID)
	if err != nil || (membership != "join" && membership != "invite") {
		return nil, types.ErrForbidden
	}

	return &MakeLeaveResult{
		RoomVersion: canal.Versao,
		Sender:      userID,
		RoomID:      roomID,
		Origin:      f.serverName,
		Timestamp:   time.Now().UnixMilli(),
	}, nil
}

func (f *FederationService) ProcessSendLeave(ctx context.Context, roomID string, leaveEvent *domain.Evento) error {
	canal, err := f.canalStore.GetByID(ctx, roomID)
	if err != nil {
		return fmt.Errorf("failed to check room: %w", err)
	}
	if canal == nil {
		return types.ErrNotFound
	}

	return f.uow.Execute(ctx, func(txCtx context.Context) error {
		if err := f.eventoStore.SaveEvento(txCtx, leaveEvent); err != nil {
			return fmt.Errorf("failed to save leave event: %w", err)
		}
		if err := f.canalStore.UpsertCurrentState(txCtx, roomID, "m.room.member", leaveEvent.Sender, leaveEvent.ID); err != nil {
			return fmt.Errorf("failed to upsert current state: %w", err)
		}
		if err := f.canalStore.UpsertMembership(txCtx, roomID, leaveEvent.Sender, "leave", leaveEvent.ID); err != nil {
			return fmt.Errorf("failed to upsert membership: %w", err)
		}
		return nil
	})
}

func (f *FederationService) ProcessInvite(ctx context.Context, roomID string, inviteEvent *domain.Evento) error {
	err := f.uow.Execute(ctx, func(txCtx context.Context) error {
		// checa se o canal existe
		canal, err := f.canalStore.GetByID(txCtx, roomID)
		if err != nil && !errors.Is(err, types.ErrNotFound) {
			return fmt.Errorf("Could not check the room: %w", err)
		}

		if canal == nil {
			_, err := f.canalStore.Create(txCtx, roomID, inviteEvent.Sender)
			if err != nil {
				return fmt.Errorf("could not create room: %w", err)
			}
		}

		if err := f.eventoStore.SaveEvento(txCtx, inviteEvent); err != nil {
			return fmt.Errorf("failed to save invite event: %w", err)
		}

		if inviteEvent.StateKey != nil {
			if err := f.canalStore.UpsertCurrentState(txCtx, roomID, "m.room.member", *inviteEvent.StateKey, inviteEvent.ID); err != nil {
				return fmt.Errorf("failed to upsert current state: %w", err)
			}

			if err := f.canalStore.UpsertMembership(txCtx, roomID, *inviteEvent.StateKey, "invite", inviteEvent.ID); err != nil {
				return fmt.Errorf("failed to upsert membership: %w", err)
			}
		}
		return nil
	})
	return err
}

// GetRoomStateSnapShot retorna um snapshot do estado da sala no momento do eventID
func (f *FederationService) GetRoomStateSnapShot(ctx context.Context, roomID, eventID string) (*RoomStateResponse, error) {

	// Verifica se evento existe
	exists, err := f.eventoStore.CheckEventoExists(ctx, eventID)
	if err != nil || !exists {
		return nil, fmt.Errorf("event not found or db error: %w", err)
	}

	// Pede snapshot
	pdus, authChain, err := f.eventoStore.GetStateAndAuthChainEvents(ctx, roomID, eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch state snapshot: %w", err)
	}

	return &RoomStateResponse{
		PDUs:      pdus,
		AuthChain: authChain,
	}, nil

}

// GetStateIDsForEvent recolhe o estado da sala no momento do eventID e a sua cadeia de autorização
func (f *FederationService) GetStateIDsForEvent(ctx context.Context, roomID, eventID string) ([]string, []string, error) {

	// 1. Validar se o evento existe e pertence a esta sala
	exists, err := f.eventoStore.CheckEventoExists(ctx, eventID)
	if err != nil || !exists {
		return nil, nil, fmt.Errorf("event not found or db error: %w", err)
	}

	// 2. Obter as listas de IDs da base de dados
	pduIDs, authIDs, err := f.eventoStore.GetStateAndAuthChainIDs(ctx, roomID, eventID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch state ids: %w", err)
	}

	return pduIDs, authIDs, nil
}

// HandleBackfill procura os eventos anteriores na árvore (DAG) para enviar a outro servidor
func (f *FederationService) HandleBackfill(ctx context.Context, roomID string, eventIDs []string, limit int) (*BackfillResult, error) {
	// Pede à base de dados para descer a árvore recursivamente
	eventos, err := f.eventoStore.GetEventsSince(ctx, roomID, limit, eventIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch backfill events: %w", err)
	}

	// Constrói o resultado com os metadados necessários
	resp := &BackfillResult{
		Origin:         f.serverName,
		OriginServerTS: time.Now().UnixMilli(),
		PDUs:           eventos,
	}

	return resp, nil
}

// HandleGetMissingEvents atende a pedidos de outros servidores que precisam preencher buracos no seu histórico
func (f *FederationService) HandleGetMissingEvents(ctx context.Context, roomID string, req GetMissingEventsRequest) (*GetMissingEventsResponse, error) {

	eventos, err := f.eventoStore.GetMissingEvents(ctx, roomID, req.EarliestEvents, req.LatestEvents, req.Limit, req.MinDepth)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve missing events: %w", err)
	}

	// Opcional: Se a base de dados não encontrar nada, garantimos que devolve um array vazio e não null
	if eventos == nil {
		eventos = []domain.Evento{}
	}

	return &GetMissingEventsResponse{
		Events: eventos,
	}, nil
}

// FetchRemoteMedia busca um arquivo de mídia hospedado em um servidor Matrix remoto, para
// implementar o proxy de GET /_matrix/client/v1/media/download/{serverName}/{mediaId} quando
// serverName não é o nosso próprio servidor
// O io.ReadCloser retornado envolve a conexão HTTP inteira: fechar ele fecha o socket também,
// então o chamador NÃO deve fechar resp.Body separadamente
func (f *FederationService) FetchRemoteMedia(ctx context.Context, destServerName, mediaID string) (io.ReadCloser, string, string, error) {
	targetHost, err := util.ResolveServerName(destServerName)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to resolve remote server %s: %w", destServerName, err)
	}

	uri := fmt.Sprintf("/_matrix/federation/v1/media/download/%s", mediaID)

	// Requisição GET sem corpo, assinamos com um payload vazio, que é o padrão do
	// protocolo Matrix (X-Matrix) para requisições sem body
	authHeader, err := util.GenerateS2SAuthHeader(f.serverName, f.keyID, f.privateKey, "GET", uri, destServerName, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to sign media request: %w", err)
	}

	reqURL := buildFederationURL(targetHost, uri)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to contact remote server %s: %w", destServerName, err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", "", fmt.Errorf("remote server %s returned status %d: %s", destServerName, resp.StatusCode, string(bodyBytes))
	}

	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		resp.Body.Close()
		return nil, "", "", fmt.Errorf("response from remote server %s is not multipart/mixed (Content-Type=%q): %v", destServerName, resp.Header.Get("Content-Type"), err)
	}

	mr := multipart.NewReader(resp.Body, params["boundary"])

	// Primeira parte: metadados JSON do MSC3916 (normalmente vazio, ou info de redirect). (Ignoramos)
	if _, err := mr.NextPart(); err != nil {
		resp.Body.Close()
		return nil, "", "", fmt.Errorf("failed to read metadata part from multipart response: %w", err)
	}

	// Segunda parte: o arquivo em si
	filePart, err := mr.NextPart()
	if err != nil {
		resp.Body.Close()
		return nil, "", "", fmt.Errorf("failed to read file part from multipart response: %w", err)
	}

	contentType := filePart.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	filename := ""
	if _, dispParams, err := mime.ParseMediaType(filePart.Header.Get("Content-Disposition")); err == nil {
		filename = dispParams["filename"]
	}

	return &remoteMediaReadCloser{part: filePart, resp: resp}, contentType, filename, nil
}

// remoteMediaReadCloser adapta um multipart.Part (que não tem Close) para io.ReadCloser,
// garantindo que fechar o resultado também feche a conexão HTTP subjacente (resp.Body).
// Sem isso, a conexão ficaria vazando até o garbage collector eventualmente liberá-la
type remoteMediaReadCloser struct {
	part *multipart.Part
	resp *http.Response
}

func (r *remoteMediaReadCloser) Read(p []byte) (int, error) {
	return r.part.Read(p)
}

func (r *remoteMediaReadCloser) Close() error {
	return r.resp.Body.Close()
}

type OutboundMakeJoinResponse struct {
	RoomVersion string        `json:"room_version"`
	Event       domain.Evento `json:"event"`
}

type OutboundSendJoinResponse struct {
	StateEvents []domain.Evento `json:"state"`
	AuthChain   []domain.Evento `json:"auth_chain"`
}

// MakeJoinCall hits GET /_matrix/federation/v1/make_join/{roomId}/{userId} on a remote host
func (f *FederationService) MakeJoinCall(ctx context.Context, remoteServer, roomID, userID string) (*domain.Evento, error) {
	targetHost, err := util.ResolveServerName(remoteServer)
	if err != nil {
		return nil, err
	}

	// Supported versions your server handles (e.g., "11" as seen in canal_storage.go)
	uri := fmt.Sprintf("/_matrix/federation/v1/make_join/%s/%s?ver=11", roomID, userID)

	authHeader, err := util.GenerateS2SAuthHeader(f.serverName, f.keyID, f.privateKey, "GET", uri, remoteServer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign make_join request: %w", err)
	}

	reqURL := buildFederationURL(targetHost, uri)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote server rejected make_join: %d - %s", resp.StatusCode, string(body))
	}

	var makeJoinResult OutboundMakeJoinResponse
	if err := json.NewDecoder(resp.Body).Decode(&makeJoinResult); err != nil {
		return nil, err
	}

	return &makeJoinResult.Event, nil
}

// OutboundInviteRequest é o payload enviado a PUT /_matrix/federation/v2/invite/{roomId}/{eventId}
// em um homeserver remoto, no mesmo formato esperado por federation.InviteRequest
type OutboundInviteRequest struct {
	RoomVersion     string                  `json:"room_version"`
	Event           json.RawMessage         `json:"event"`
	InviteRoomState []domain.StrippedEvento `json:"invite_room_state"`
}

type OutboundInviteResponse struct {
	Event json.RawMessage `json:"event"`
}

// SendInviteCall chama PUT /_matrix/federation/v2/invite/{roomId}/{eventId} no homeserver
// remoto do convidado, pedindo que ele valide e contra-assine o evento de convite antes
// deste ser aceito como válido na sala
func (f *FederationService) SendInviteCall(ctx context.Context, remoteServer, roomID, roomVersion string, inviteEvent *domain.Evento, inviteRoomState []domain.StrippedEvento) (*domain.Evento, error) {
	targetHost, err := util.ResolveServerName(remoteServer)
	if err != nil {
		return nil, err
	}

	uri := fmt.Sprintf("/_matrix/federation/v2/invite/%s/%s", roomID, inviteEvent.ID)

	eventBytes, err := util.CanonicalJSON(inviteEvent)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize invite event: %w", err)
	}

	if inviteRoomState == nil {
		inviteRoomState = []domain.StrippedEvento{}
	}

	payload := OutboundInviteRequest{
		RoomVersion:     roomVersion,
		Event:           eventBytes,
		InviteRoomState: inviteRoomState,
	}

	payloadBytes, err := util.CanonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize invite payload: %w", err)
	}

	// fmt.Printf("[DEBUG] keyId: %s privateKey: %s", f.keyID, f.privateKey)
	authHeader, err := util.GenerateS2SAuthHeader(f.serverName, f.keyID, f.privateKey, "PUT", uri, remoteServer, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign invite request: %w", err)
	}

	reqURL := buildFederationURL(targetHost, uri)
	req, err := http.NewRequestWithContext(ctx, "PUT", reqURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to contact remote server %s: %w", remoteServer, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		// Tenta identificar o caso específico de versão de sala incompatível (400 M_UNSUPPORTED_ROOM_VERSION)
		var apiErr struct {
			Errcode string `json:"errcode"`
		}
		_ = json.Unmarshal(body, &apiErr)
		if apiErr.Errcode == "M_UNSUPPORTED_ROOM_VERSION" {
			return nil, ErrIncompatibleRoomVersion
		}

		return nil, fmt.Errorf("remote server rejected invite: %d - %s", resp.StatusCode, string(body))
	}

	var inviteResult OutboundInviteResponse
	if err := json.NewDecoder(resp.Body).Decode(&inviteResult); err != nil {
		return nil, fmt.Errorf("failed to decode invite response: %w", err)
	}

	var signedEvent domain.Evento
	if err := json.Unmarshal(inviteResult.Event, &signedEvent); err != nil {
		return nil, fmt.Errorf("failed to parse signed invite event: %w", err)
	}

	return &signedEvent, nil
}

type SendJoinRequest struct {
	Content        json.RawMessage `json:"content"`
	Origin         string          `json:"origin"`
	OriginServerTS int64           `json:"origin_server_ts"`
	Sender         string          `json:"sender"`
	StateKey       string          `json:"state_key"`
	Type           string          `json:"type"`
	RoomID         string          `json:"room_id"`
	EventID        string          `json:"event_id"`
	Signatures     json.RawMessage `json:"signatures"`

	Depth      int64    `json:"depth"`
	PrevEvents []string `json:"prev_events"`
	AuthEvents []string `json:"auth_events"`
}

// SendJoinCall hits PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}
func (f *FederationService) SendJoinCall(ctx context.Context, remoteServer, roomID string, signedEvent *domain.Evento) (*OutboundSendJoinResponse, error) {
	targetHost, err := util.ResolveServerName(remoteServer)
	if err != nil {
		return nil, err
	}

	uri := fmt.Sprintf("/_matrix/federation/v1/send_join/%s/%s", roomID, signedEvent.ID)

	payload := SendJoinRequest{
		Content:        signedEvent.Content,
		Origin:         f.serverName,
		OriginServerTS: signedEvent.OrigemServidorTS,
		Sender:         signedEvent.Sender,
		Type:           "m.room.member",
		RoomID:         roomID,
		EventID:        signedEvent.ID,
		Signatures:     signedEvent.Signatures,
		Depth:          signedEvent.Depth,
		PrevEvents:     signedEvent.PrevEventos,
		AuthEvents:     signedEvent.AuthEventos,
	}

	if signedEvent.StateKey != nil {
		payload.StateKey = *signedEvent.StateKey
	} else {
		payload.StateKey = ""
	}

	payloadBytes, err := util.CanonicalJSON(payload)
	if err != nil {
		return nil, err
	}

	authHeader, err := util.GenerateS2SAuthHeader(f.serverName, f.keyID, f.privateKey, "PUT", uri, remoteServer, signedEvent)
	if err != nil {
		return nil, fmt.Errorf("failed to sign send_join request: %w", err)
	}

	reqURL := buildFederationURL(targetHost, uri)
	req, err := http.NewRequestWithContext(ctx, "PUT", reqURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote server rejected send_join: %d - %s", resp.StatusCode, string(body))
	}

	var sendJoinResult OutboundSendJoinResponse
	if err := json.NewDecoder(resp.Body).Decode(&sendJoinResult); err != nil {
		return nil, err
	}

	return &sendJoinResult, nil
}

// OutboundQueryDirectoryResponse é a resposta de GET /_matrix/federation/v1/query/directory
type OutboundQueryDirectoryResponse struct {
	RoomID  string   `json:"room_id"`
	Servers []string `json:"servers"`
}

// QueryDirectory implementa RemoteDirectoryResolver: consulta o homeserver remoto dono do
// alias via GET /_matrix/federation/v1/query/directory
func (f *FederationService) QueryDirectory(ctx context.Context, remoteServer, roomAlias string) (string, []string, error) {
	targetHost, err := util.ResolveServerName(remoteServer)
	if err != nil {
		return "", nil, err
	}

	uri := fmt.Sprintf("/_matrix/federation/v1/query/directory?room_alias=%s", url.QueryEscape(roomAlias))

	authHeader, err := util.GenerateS2SAuthHeader(f.serverName, f.keyID, f.privateKey, "GET", uri, remoteServer, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign query/directory request: %w", err)
	}

	reqURL := buildFederationURL(targetHost, uri)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to contact remote server %s: %w", remoteServer, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil, types.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("remote server rejected query/directory: %d - %s", resp.StatusCode, string(body))
	}

	var result OutboundQueryDirectoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("failed to decode query/directory response: %w", err)
	}

	return result.RoomID, result.Servers, nil
}

// OutboundKeysQueryRequest é o payload de POST /_matrix/federation/v1/user/keys/query
type OutboundKeysQueryRequest struct {
	DeviceKeys map[string][]string `json:"device_keys"`
}

// OutboundKeysQueryResponse é a resposta de POST /_matrix/federation/v1/user/keys/query
type OutboundKeysQueryResponse struct {
	DeviceKeys      map[string]map[string]json.RawMessage `json:"device_keys"`
	MasterKeys      map[string]json.RawMessage            `json:"master_keys,omitempty"`
	SelfSigningKeys map[string]json.RawMessage            `json:"self_signing_keys,omitempty"`
}

// QueryKeysCall consulta as chaves de identidade de dispositivos de usuários hospedados em remoteServer
func (f *FederationService) QueryKeysCall(ctx context.Context, remoteServer string, deviceKeys map[string][]string) (*OutboundKeysQueryResponse, error) {
	targetHost, err := util.ResolveServerName(remoteServer)
	if err != nil {
		return nil, err
	}

	uri := "/_matrix/federation/v1/user/keys/query"
	payload := OutboundKeysQueryRequest{DeviceKeys: deviceKeys}

	payloadBytes, err := util.CanonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize keys/query payload: %w", err)
	}

	authHeader, err := util.GenerateS2SAuthHeader(f.serverName, f.keyID, f.privateKey, "POST", uri, remoteServer, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign keys/query request: %w", err)
	}

	reqURL := buildFederationURL(targetHost, uri)
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to contact remote server %s: %w", remoteServer, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote server rejected keys/query: %d - %s", resp.StatusCode, string(body))
	}

	var result OutboundKeysQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode keys/query response: %w", err)
	}

	return &result, nil
}

// OutboundKeysClaimRequest é o payload de POST /_matrix/federation/v1/user/keys/claim
type OutboundKeysClaimRequest struct {
	OneTimeKeys map[string]map[string]string `json:"one_time_keys"`
}

// OutboundKeysClaimResponse é a resposta de POST /_matrix/federation/v1/user/keys/claim
type OutboundKeysClaimResponse struct {
	OneTimeKeys map[string]map[string]map[string]json.RawMessage `json:"one_time_keys"`
}

// ClaimKeysCall reivindica one-time keys de dispositivos hospedados em remoteServer
func (f *FederationService) ClaimKeysCall(ctx context.Context, remoteServer string, oneTimeKeys map[string]map[string]string) (map[string]map[string]map[string]json.RawMessage, error) {
	targetHost, err := util.ResolveServerName(remoteServer)
	if err != nil {
		return nil, err
	}

	uri := "/_matrix/federation/v1/user/keys/claim"
	payload := OutboundKeysClaimRequest{OneTimeKeys: oneTimeKeys}

	payloadBytes, err := util.CanonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize keys/claim payload: %w", err)
	}

	authHeader, err := util.GenerateS2SAuthHeader(f.serverName, f.keyID, f.privateKey, "POST", uri, remoteServer, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign keys/claim request: %w", err)
	}

	reqURL := buildFederationURL(targetHost, uri)
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to contact remote server %s: %w", remoteServer, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote server rejected keys/claim: %d - %s", resp.StatusCode, string(body))
	}

	var result OutboundKeysClaimResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode keys/claim response: %w", err)
	}

	return result.OneTimeKeys, nil
}

// resolveStateAtIngestion calculates the consensus state map across all prev_events of an incoming PDU.
func (f *FederationService) resolveStateAtIngestion(ctx context.Context, roomID string, prevEvents []string) (domain.StateMap, error) {
	if len(prevEvents) == 0 {
		// Genesis event (m.room.create); room state is empty
		return make(domain.StateMap), nil
	}

	stateSets := make([]domain.StateMap, 0, len(prevEvents))
	allAuthEventIDs := make(map[string]bool)
	allStateEventIDs := make(map[string]bool)

	// 1. Fetch state IDs and auth chains for each branch in prev_events
	for _, prevID := range prevEvents {
		stateIDs, authIDs, err := f.eventoStore.GetStateAndAuthChainIDs(ctx, roomID, prevID)
		if err != nil {
			log.Printf("[Federation] Could not fetch state for branch %s: %v", prevID, err)
			continue
		}

		branchState := make(domain.StateMap)
		for _, id := range stateIDs {
			allStateEventIDs[id] = true
			// We will map tuples once we load the Evento objects below
		}
		for _, id := range authIDs {
			allAuthEventIDs[id] = true
		}

		// Store temporary list of state IDs for this branch
		// We need to fetch the actual events to get their (type, state_key) tuples
		stateSets = append(stateSets, branchState)
	}

	if len(stateSets) == 0 {
		return nil, fmt.Errorf("could not resolve state from any prev_events")
	}

	// 2. Batch load all state and auth events from database
	eventsMap := make(map[string]*domain.Evento)
	authEventsMap := make(map[string]*domain.Evento)

	for id := range allStateEventIDs {
		if ev, err := f.eventoStore.GetEvento(ctx, id); err == nil && ev != nil {
			eventsMap[id] = ev
		}
	}
	for id := range allAuthEventIDs {
		if ev, err := f.eventoStore.GetEvento(ctx, id); err == nil && ev != nil {
			authEventsMap[id] = ev
		}
	}

	// 3. Populate the StateMap tuples for each branch now that we have the Evento objects
	for idx, prevID := range prevEvents {
		if idx >= len(stateSets) {
			break
		}
		stateIDs, _, _ := f.eventoStore.GetStateAndAuthChainIDs(ctx, roomID, prevID)
		for _, id := range stateIDs {
			if ev, exists := eventsMap[id]; exists {
				tuple := domain.NewStateTuple(ev.Tipo, ev.StateKey)
				stateSets[idx][tuple] = id
			}
		}
	}

	// 4. If only 1 branch exists or all branches are identical, no resolution needed!
	if len(stateSets) == 1 {
		return stateSets[0], nil
	}

	// 5. Execute State Resolution v2 across the conflicting branches
	input := domain.StateResolutionInput{
		RoomID:        roomID,
		StateSets:     stateSets,
		AuthEventsMap: authEventsMap,
		EventsMap:     eventsMap,
	}

	resolvedState, err := f.stateResolver.Resolve(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("state resolution v2 failed: %w", err)
	}

	return resolvedState, nil
}

// updateRoomStateAndMembership ensures both the generic state map and the dedicated
// membership view stay synchronized whenever a state event is processed.
func (f *FederationService) updateRoomStateAndMembership(ctx context.Context, pdu *domain.Evento) error {
	if pdu.StateKey == nil {
		return nil
	}

	// 1. Update the generic state map
	if err := f.canalStore.UpsertCurrentState(ctx, pdu.CanalID, pdu.Tipo, *pdu.StateKey, pdu.ID); err != nil {
		return fmt.Errorf("falha ao atualizar estado da sala: %w", err)
	}

	// 2. If it's a membership event, keep the membership table in sync
	if pdu.Tipo == "m.room.member" {
		var content struct {
			Membership string `json:"membership"`
		}
		if err := json.Unmarshal(pdu.Content, &content); err == nil && content.Membership != "" {
			if err := f.canalStore.UpsertMembership(ctx, pdu.CanalID, *pdu.StateKey, content.Membership, pdu.ID); err != nil {
				return fmt.Errorf("falha ao atualizar membership: %w", err)
			}
		}
	}

	return nil
}
// DirectToDeviceEduContent é o conteúdo da EDU m.direct_to_device (S2S)
type DirectToDeviceEduContent struct {
	MessageID string                                `json:"message_id"`
	Messages  map[string]map[string]json.RawMessage `json:"messages"`
	Sender    string                                `json:"sender"`
	Type      string                                `json:"type"`
}

// SendToDeviceCall envia mensagens send-to-device pra usuários hospedados em remoteServer via
// uma EDU m.direct_to_device dentro de uma transação de federação. Best-effort: erros só são logados
// (diferente do pipeline de PDUs, não há fila de retry aqui ainda).
func (f *FederationService) SendToDeviceCall(ctx context.Context, remoteServer, sender, eventType string, messages map[string]map[string]json.RawMessage) {
	targetHost, err := util.ResolveServerName(remoteServer)
	if err != nil {
		log.Printf("[Federation] SendToDeviceCall: failed to resolve %s: %v", remoteServer, err)
		return
	}

	txnID := fmt.Sprintf("%d", time.Now().UnixMilli())
	uri := fmt.Sprintf("/_matrix/federation/v1/send/%s", txnID)

	eduContentBytes, err := json.Marshal(DirectToDeviceEduContent{
		MessageID: txnID,
		Messages:  messages,
		Sender:    sender,
		Type:      eventType,
	})
	if err != nil {
		log.Printf("[Federation] SendToDeviceCall: failed to marshal EDU content: %v", err)
		return
	}

	txnPayload := map[string]any{
		"origin":           f.serverName,
		"origin_server_ts": time.Now().UnixMilli(),
		"pdus":             []domain.Evento{},
		"edus": []map[string]any{
			{"edu_type": "m.direct_to_device", "content": json.RawMessage(eduContentBytes)},
		},
	}

	txnBytes, err := util.CanonicalJSON(txnPayload)
	if err != nil {
		log.Printf("[Federation] SendToDeviceCall: failed to canonicalize payload: %v", err)
		return
	}

	authHeader, err := util.GenerateS2SAuthHeader(f.serverName, f.keyID, f.privateKey, "PUT", uri, remoteServer, txnPayload)
	if err != nil {
		log.Printf("[Federation] SendToDeviceCall: failed to sign request: %v", err)
		return
	}

	reqURL := buildFederationURL(targetHost, uri)
	req, err := http.NewRequestWithContext(ctx, "PUT", reqURL, bytes.NewBuffer(txnBytes))
	if err != nil {
		log.Printf("[Federation] SendToDeviceCall: failed to build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Federation] SendToDeviceCall: failed to contact %s: %v", remoteServer, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[Federation] SendToDeviceCall: remote server rejected transaction: %d - %s", resp.StatusCode, string(body))
	}
}
