package usecase

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

type DirectoryService struct {
	dirStore   DirectoryStorage
	userStore  UsuarioStorage
	canalStore CanalStorage
}

func NewDirectoryService(dirStore DirectoryStorage, userStore UsuarioStorage, canalStore CanalStorage) *DirectoryService {
	return &DirectoryService{
		dirStore:   dirStore,
		userStore:  userStore,
		canalStore: canalStore,
	}
}

func (s *DirectoryService) ListPublic(ctx context.Context, term string, limit int, offset int) (*domain.PublicRoomsChunck, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	// busca limit+1 para detectar se há próxima página
	entries, totalCount, err := s.dirStore.SearchDirectory(ctx, term, limit+1, offset)
	if err != nil {
		return nil, err
	}

	hasMore := len(entries) > limit
	if hasMore {
		entries = entries[:limit]
	}

	// Garante que chunk nunca seja null no JSON
	if entries == nil {
		entries = []domain.PublicRoomEntry{}
	}

	response := domain.PublicRoomsChunck{
		Chunk:                  entries,
		TotalRoomCountEstimate: totalCount,
	}

	if hasMore {
		response.NextBatch = fmt.Sprintf("%d", offset+limit)
	}
	// PrevBatch só aparece se não estivermos na primeira página
	if offset > 0 {
		prev := offset - limit
		if prev < 0 {
			prev = 0
		}
		response.PrevBatch = fmt.Sprintf("%d", prev)
	}

	return &response, nil
}

func (s *DirectoryService) SearchProfiles(ctx context.Context, query string, limit int) ([]domain.Profile, error) {
	userID := ctx.Value(types.UserIDKey).(string)
	if query == "" {
		return nil, types.ErrInvalidSearchTerm
	}

	allowedRooms, err := s.canalStore.GetUserJoinedRooms(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("Failed to verify user membership: %w", err)
	}
	// +1 para saber se há mais resultados
	filter := SearchFilter{
		IDCanais:  allowedRooms,
		Term:      query,
		Limit:     limit + 1,
		NextToken: "",
	}
	return s.userStore.SearchProfiles(ctx, filter)
}
