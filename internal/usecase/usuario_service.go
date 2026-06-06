package usecase

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/jackc/pgx/v5"
)

type UsuarioService struct {
	eventoStore  EventoStorage
	usuarioStore UsuarioStorage
	canalStore   CanalStorage
}

func NewUsuarioService(eventoStore EventoStorage, usuarioStore UsuarioStorage, canalStore CanalStorage) *UsuarioService {
	return &UsuarioService{
		eventoStore:  eventoStore,
		usuarioStore: usuarioStore,
		canalStore:   canalStore,
	}
}

func (u *UsuarioService) GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error) {
	usuario, err := u.usuarioStore.GetProfileByID(ctx, userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return usuario, nil
}

func (u *UsuarioService) SearchProfiles(ctx context.Context, term string, limit int) ([]domain.Profile, error) {
	userID := ctx.Value(types.UserIDKey).(string)
	if term == "" {
		return nil, types.ErrInvalidSearchTerm
	}

	allowedRooms, err := u.canalStore.GetUserJoinedRooms(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("Failed to verify user membership: %w", err)
	}
	filter := SearchFilter{
		IDCanais:  allowedRooms,
		Term:      term,
		Limit:     limit,
		NextToken: "",
	}
	return u.usuarioStore.SearchProfiles(ctx, filter)
}

func (u *UsuarioService) Sync(ctx context.Context, since domain.SyncToken, timeout time.Duration) ([]domain.Evento, domain.SyncToken, error) {
	// Lógica de Long-Polling
	if req.Since.RoomEvents != 0 {
		hasEvents, err := h.eventoStore.CheckNew(ctx, userID, req.Since)
		if err != nil {
			httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "could not check new events")
			return
		}

		if !hasEvents && req.Timeout > 0 {
			// sem eventos, long-polling
			ch := h.notifier.Subscribe(userID)
			defer h.notifier.Unsubscribe(userID, ch)

			select {
			case <-ch:
				// Novo evento, pode acessar o banco
			case <-time.After(req.Timeout):
				// Deu timeout antes de um novo evento, cria novo token e retorna
				maxGlobal, _ := h.eventoStore.GetMaxGlobalStreamOrdering(ctx)
				if maxGlobal > req.Since.RoomEvents {
					req.Since.RoomEvents = maxGlobal
				}
				response := createSyncResponse()
				response.NextBatch = req.Since
				httputil.WriteJSON(w, http.StatusOK, response)
				return
			case <-ctx.Done():
				// o client se desconectou
				return
			}
		}
	}

	// accesso ao banco
	events, newToken, err := h.eventoStore.GetSince(ctx, userID, req.Since)
}
