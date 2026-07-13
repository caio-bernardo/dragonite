package usecase

import (
	"context"
	"io"

	"github.com/caio-bernardo/dragonite/internal/domain"
)

type SearchFilter struct {
	IDCanais  []string // canais a procurar
	Term      string   //termo de pesquisa
	Limit     int      // limite de resultados
	NextToken string   // paginação
}

type UsuarioStorage interface {
	// Cria um novo domain.Usuario, acompanhado de um domain.Profile
	CreateUsuarioAndProfile(ctx context.Context, userProps domain.Usuario) (*domain.Usuario, error)
	GetUsuarioByID(ctx context.Context, userID string) (*domain.Usuario, error)
	GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error)
	UpdateProfile(ctx context.Context, profile domain.Profile) error
	SearchProfiles(ctx context.Context, filter SearchFilter) ([]domain.Profile, error)
	AddDirectMessage(ctx context.Context, senderID, receiverID string, roomID string) error
	// AccountData operations
	SaveAccountData(ctx context.Context, account domain.AccountData) error
	GetAccountData(ctx context.Context, userID, roomID, tipo string) (*domain.AccountData, error)
	// Returns global account data for a user
	GetGlobalAccountData(ctx context.Context, userID string) ([]domain.AccountData, error)
	GetAccountDataOfCanal(ctx context.Context, userID string, canalID string) ([]domain.AccountData, error)

	GetStateAndAuthChainIDs(ctx context.Context, roomID string, eventID string) ([]string, []string, error)
	// Returns the invites received by this user
	GetInviteEventsSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error)
}

type CanalStorage interface {
	Create(ctx context.Context, roomID, userID string) (*domain.Canal, error)
	// Get all unique servers from users in the room
	GetCanalParticipatingServers(ctx context.Context, canalID string) ([]string, error)
	GetByID(ctx context.Context, canalID string) (*domain.Canal, error)
	// Get join_rules from a room
	GetJoinRule(ctx context.Context, roomID string) (string, error)
	// Get all room ids joined by a user
	GetUserJoinedRooms(ctx context.Context, userID string) ([]string, error)
	// Get all room ids the user has left
	GetUserLeftRooms(ctx context.Context, userID string) ([]string, error)
	// Get a user membership state
	GetUserMembership(ctx context.Context, roomID, userID string) (string, error)
	// Get a room state event ID
	GetStateEventID(ctx context.Context, canalID string, stateType, stateKey string) (string, bool)
	UpsertMembership(ctx context.Context, roomID, userID, membership, id_evento string) error
	UpsertCurrentState(ctx context.Context, canalID, stateType, stateKey, eventID string) error
	GetAllPublic(ctx context.Context, offset, limit int) ([]domain.Canal, error)
	UpdateForwardExtremities(ctx context.Context, canalID string, newEventID string, prevEvents []string) error
	GetForwardExtremities(ctx context.Context, canalID string) ([]string, error)
	SaveAlias(ctx context.Context, roomID, fullAlias string) error
}

type EventoStorage interface {
	// Retorna todos os eventos com base em SyncToken. Retorna uma lista de eventos ordenados com base em StreamOrdering
	GetSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error)
	GetMaxDepthFromEventos(ctx context.Context, eventIDs []string) (int64, error)
	SaveEvento(ctx context.Context, event *domain.Evento) error
	GetEvento(ctx context.Context, eventID string) (*domain.Evento, error)
	GetEventsSince(ctx context.Context, roomID string, limit int, eventIDs []string) ([]domain.Evento, error)
	GetEventsOfCanalSince(ctx context.Context, userID string, roomID string, since domain.SyncToken) ([]domain.Evento, error)
	CheckEventoExists(ctx context.Context, eventID string) (bool, error)
	GetCurrentStateEvents(ctx context.Context, roomID string) ([]domain.Evento, error)
	GetStateAndAuthChainIDs(ctx context.Context, roomID string, eventID string) ([]string, []string, error)
	GetMissingEvents(ctx context.Context, roomID string, earliestEvents, latestEvents []string, limit int, minDepth int64) ([]domain.Evento, error)
	// SaveReceipt atualiza o ponteiro de leitura de um utilizador numa sala
	SaveReceipt(ctx context.Context, userID, roomID, receiptType, eventID string, ts int64) error
	GetRoomMessagesHistory(ctx context.Context, roomID string, fromToken int64, dir string, limit int) ([]domain.Evento, error)
	// Get Events since the user has left
	GetEventsOfCanalSinceLeft(ctx context.Context, userID string, roomID string, since domain.SyncToken) ([]domain.Evento, error)
	GetStateAndAuthChainEvents(ctx context.Context, roomID string, userID string) ([]domain.Evento, []domain.Evento, error)
}

type DeviceStorage interface {
	GetDeviceByID(ctx context.Context, deviceID string) (*domain.Dispositivo, error)
	GetDispositivoByRefreshToken(ctx context.Context, refreshToken string) (*domain.Dispositivo, error)
	UpsertDispositivo(ctx context.Context, device *domain.Dispositivo) error
	UpdateDevice(ctx context.Context, device *domain.Dispositivo) error
}

type SystemStorage interface {
	PingDB() map[string]string
}

type DirectoryStorage interface {
	SearchDirectory(ctx context.Context, term string, limit, offset int) ([]domain.PublicRoomEntry, int, error)
}

type Notifier interface {
	WaitForEvents(ctx context.Context, userID string) error
}

// Executes operations inside a transaction. Commit if succeeds or rollback in failure
type WorkUnit interface {
	Execute(ctx context.Context, fn func(txCtx context.Context) error) error
}

// MidiaStorage define as operações de persistência de metadados de mídia no banco de dados.
// Os arquivos em si são armazenados via FileStorage (MinIO).
type MidiaStorage interface {
	// SaveMidia persiste os metadados de um arquivo de mídia recém-carregado.
	SaveMidia(ctx context.Context, midia *domain.Midia) error
	// GetMidiaByID recupera os metadados pelo par (origin, idMidia) — chave primária composta.
	GetMidiaByID(ctx context.Context, origin, idMidia string) (*domain.Midia, error)
}

// FileStorage define as operações de armazenamento de arquivos binários.
// Implementado pelo MinioStorage em internal/infrastructure/minio.
type FileStorage interface {
	// Upload armazena o conteúdo do arquivo usando mediaID como chave.
	Upload(ctx context.Context, mediaID string, content io.Reader, size int64, contentType string) error
	// Download retorna um ReadCloser com o conteúdo do arquivo, o chamador deve fechá-lo
	Download(ctx context.Context, mediaID string) (io.ReadCloser, error)
	// Delete remove permanentemente o arquivo do object storage.
	Delete(ctx context.Context, mediaID string) error
}

// RemoteMediaFetcher busca um arquivo de mídia hospedado em OUTRO servidor Matrix via federação (S2S)
// Deixar como interface (em vez de acoplar *FederationService direto)
// permite testar o MediaService com um fake, sem precisar de rede.
type RemoteMediaFetcher interface {
	// FetchRemoteMedia busca o arquivo mediaID hospedado em destServerName
	// content deve ser fechado pelo chamador e contentType e filename
	// podem vir vazios se o servidor remoto não os informar
	FetchRemoteMedia(ctx context.Context, destServerName, mediaID string) (content io.ReadCloser, contentType, filename string, err error)
}
