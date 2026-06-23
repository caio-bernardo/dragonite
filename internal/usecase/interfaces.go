package usecase

import (
	"context"

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
	// Get a user membership state
	GetUserMembership(ctx context.Context, roomID, userID string) (string, error)
	// Get a room state event ID
	GetStateEventID(ctx context.Context, canalID string, stateType, stateKey string) (string, bool)
	UpsertMembership(ctx context.Context, roomID, userID, membership string) error
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
	CheckEventoExists(ctx context.Context, eventID string) (bool, error)
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
