package usecase

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

type DirectoryService struct {
	dirStore    DirectoryStorage
	userStore   UsuarioStorage
	canalStore  CanalStorage
	remoteQuery RemoteDirectoryResolver
	serverName  string
}

func NewDirectoryService(dirStore DirectoryStorage, userStore UsuarioStorage, canalStore CanalStorage, remoteQuery RemoteDirectoryResolver, serverName string) *DirectoryService {
	return &DirectoryService{
		dirStore:    dirStore,
		userStore:   userStore,
		canalStore:  canalStore,
		remoteQuery: remoteQuery,
		serverName:  serverName,
	}
}

// parseAliasDomain valida o formato #local:domain de um alias e retorna o domínio.
func parseAliasDomain(alias string) (string, bool) {
	if !strings.HasPrefix(alias, "#") {
		return "", false
	}
	parts := strings.SplitN(alias[1:], ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// resolveLocal busca o room_id de um alias local e monta a lista de servidores conhecidos da sala.
func (s *DirectoryService) resolveLocal(ctx context.Context, alias string) (string, []string, error) {
	roomID, err := s.dirStore.GetRoomIDByAlias(ctx, alias)
	if err != nil {
		return "", nil, err
	}

	servers, err := s.canalStore.GetCanalParticipatingServers(ctx, roomID)
	if err != nil {
		servers = nil
	}
	// garante que o próprio servidor apareça na lista
	found := slices.Contains(servers, s.serverName)
	if !found {
		servers = append([]string{s.serverName}, servers...)
	}

	return roomID, servers, nil
}

// ResolveAlias resolve um alias pro cliente: local se o domínio bater com este servidor,
// via federação (GET /_matrix/federation/v1/query/directory) caso contrário
func (s *DirectoryService) ResolveAlias(ctx context.Context, alias string) (string, []string, error) {
	domain, ok := parseAliasDomain(alias)
	if !ok {
		return "", nil, types.ErrInvalidParam
	}

	if domain != s.serverName {
		return s.remoteQuery.QueryDirectory(ctx, domain, alias)
	}

	return s.resolveLocal(ctx, alias)
}

// ResolveLocalAlias é usado pelo endpoint de federação: só deve responder por aliases
// que pertencem a este servidor (evita loop e respeita a recomendação da spec de que
// homeservers só devem consultar aliases do domínio-alvo)
func (s *DirectoryService) ResolveLocalAlias(ctx context.Context, alias string) (string, []string, error) {
	domain, ok := parseAliasDomain(alias)
	if !ok || domain != s.serverName {
		return "", nil, types.ErrNotFound
	}
	return s.resolveLocal(ctx, alias)
}

// CreateAlias mapeia um alias local a um room_id
func (s *DirectoryService) CreateAlias(ctx context.Context, alias, roomID string) error {
	domain, ok := parseAliasDomain(alias)
	if !ok || domain != s.serverName {
		return types.ErrInvalidParam
	}

	existing, err := s.dirStore.GetRoomIDByAlias(ctx, alias)
	if err == nil {
		if existing == roomID {
			return nil
		}
		return types.ErrAlreadyInUse
	}
	if !errors.Is(err, types.ErrNotFound) {
		return err
	}

	return s.canalStore.SaveAlias(ctx, roomID, alias)
}

// DeleteAlias remove o mapeamento de um alias local
func (s *DirectoryService) DeleteAlias(ctx context.Context, alias string) error {
	domain, ok := parseAliasDomain(alias)
	if !ok || domain != s.serverName {
		return types.ErrInvalidParam
	}
	return s.dirStore.DeleteAlias(ctx, alias)
}

func (s *DirectoryService) ListPublic(ctx context.Context, server, term string, limit int, offset int) (*domain.PublicRoomsChunck, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	// Se o server pedido não é o nosso, delega via federação em vez de consultar o banco local
	if server != "" && server != s.serverName {
		return s.remoteQuery.QueryPublicRooms(ctx, server, term, limit, offset)
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
		prev := max(offset-limit, 0)
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
