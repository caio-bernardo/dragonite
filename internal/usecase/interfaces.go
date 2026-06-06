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
	GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error)
	SearchProfiles(ctx context.Context, params SearchFilter) ([]domain.Profile, error)
}

type CanalStorage interface {
	GetUserJoinedRooms(ctx context.Context, userID string) ([]string, error)
}

type EventoStorage interface {
}
