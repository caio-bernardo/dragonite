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
	CreateUsuarioAndProfile(ctx context.Context, userProps domain.Usuario) (*domain.Usuario, error)
	GetUsuarioByID(ctx context.Context, userID string) (*domain.Usuario, error)
	GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error)
	UpdateProfile(ctx context.Context, profile domain.Profile) error
	SearchProfiles(ctx context.Context, filter SearchFilter) ([]domain.Profile, error)
	AddDirectMessage(ctx context.Context, senderID, receiverID string, roomID string) error
}

type CanalStorage interface {
	Create(ctx context.Context, roomID, userID string) (*domain.Canal, error)
	GetByID(ctx context.Context, canalID string) (*domain.Canal, error)
	GetJoinRule(ctx context.Context, roomID string) (string, error)
	GetUserJoinedRooms(ctx context.Context, userID string) ([]string, error)
	GetUserMembership(ctx context.Context, userID, roomID string) (string, error)
	GetStateEventID(ctx context.Context, canalID string, stateType, stateKey string) (string, bool)
	UpsertMembership(ctx context.Context, userID, roomID, membership string) error
	UpsertCurrentState(ctx context.Context, canalID, stateType, stateKey, eventID string) error
	GetAllPublic(ctx context.Context, offset, limit int) ([]domain.Canal, error)
	UpdateForwardExtremities(ctx context.Context, canalID string, extremeties []string) error
	GetForwardExtremities(ctx context.Context, canalID string) ([]string, error)
	SaveAlias(ctx context.Context, roomID, fullAlias string) error
}

type EventoStorage interface {
	// Retorna todos os eventos com base em SyncToken. Retorna uma lista de eventos ordenados com base em StreamOrdering
	GetSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error)
	SaveEvent(ctx context.Context, event *domain.Evento) error
}

type DeviceStorage interface {
	GetDeviceByID(ctx context.Context, deviceID string) (*domain.Dispositivo, error)
	GetDispositivoByRefreshToken(ctx context.Context, refreshToken string) (*domain.Dispositivo, error)
	UpsertDispositivo(ctx context.Context, device *domain.Dispositivo) error
	UpdateDevice(ctx context.Context, device *domain.Dispositivo) error
}

type Notifier interface {
	WaitForEvents(ctx context.Context, userID string) error
}

// EventBus implementa um canal de transmissão de eventos publish-subscriber
type EventBus interface {
	Publish(ctx context.Context, canal_id string, event domain.Evento)
	PublishToUser(ctx context.Context, userID string, event domain.Evento)
	Subscribe(ctx context.Context, canal_id string) (<-chan *domain.Evento, func())
}
type DirectoryStorage interface {
	SearchDirectory(ctx context.Context, term string, limit, offset int) ([]domain.PublicRoomEntry, int, error)
}

// Executes operations inside a transaction. Commit if succeeds or rollback in failure
type WorkUnit interface {
	Execute(ctx context.Context, fn func(txCtx context.Context) error) error
}

type FederationService interface {
	QueueOutgoing(ctx context.Context, event domain.Evento) error
}
