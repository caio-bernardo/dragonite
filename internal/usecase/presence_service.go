package usecase

import (
	"context"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

// PresenceService contém a lógica para consulta e atualização do
// estado de presença dos usuários (online/offline/unavailable)
type PresenceService struct {
	presenceStore PresenceStorage
	canalStore    CanalStorage
}

func NewPresenceService(presenceStore PresenceStorage, canalStore CanalStorage) *PresenceService {
	return &PresenceService{
		presenceStore: presenceStore,
		canalStore:    canalStore,
	}
}

// GetStatus retorna o presence state de targetUserID. Um usuário só pode ver a
// presença de outro se compartilhar pelo menos uma sala com ele (ou for ele mesmo)
func (p *PresenceService) GetStatus(ctx context.Context, requesterID, targetUserID string) (*domain.Presence, error) {
	if requesterID != targetUserID {
		shared, err := p.sharesRoomWith(ctx, requesterID, targetUserID)
		if err != nil {
			return nil, err
		}
		if !shared {
			return nil, types.ErrForbidden
		}
	}

	presence, err := p.presenceStore.GetPresence(ctx, targetUserID)
	if err != nil {
		return nil, err
	}
	if presence == nil {
		return nil, types.ErrNotFound
	}
	return presence, nil
}

// SetStatus atualiza o presence state do próprio usuário autenticado
// last_active_at é sempre definido para "agora" pelo servidor, o cliente não o informa
func (p *PresenceService) SetStatus(ctx context.Context, userID string, state domain.PresenceState, statusMsg *string) error {
	if userID == "" {
		return types.ErrInvalidUserID
	}
	if !isValidPresenceState(state) {
		return types.ErrInvalidParam
	}

	presence := domain.Presence{
		IDUsuario:    userID,
		State:        state,
		StatusMsg:    statusMsg,
		LastActiveAt: time.Now().UTC(),
	}

	return p.presenceStore.UpsertPresence(ctx, presence)
}

func isValidPresenceState(s domain.PresenceState) bool {
	switch s {
	case domain.PresenceOnline, domain.PresenceOffline, domain.PresenceUnavailable:
		return true
	default:
		return false
	}
}

// sharesRoomWith verifica se dois usuários têm pelo menos uma sala em comum
// (membership "join" em ambos), usado pra decidir visibilidade de presence
func (p *PresenceService) sharesRoomWith(ctx context.Context, userA, userB string) (bool, error) {
	roomsA, err := p.canalStore.GetUserJoinedRooms(ctx, userA)
	if err != nil {
		return false, err
	}
	if len(roomsA) == 0 {
		return false, nil
	}

	roomsB, err := p.canalStore.GetUserJoinedRooms(ctx, userB)
	if err != nil {
		return false, err
	}

	roomSetB := make(map[string]struct{}, len(roomsB))
	for _, r := range roomsB {
		roomSetB[r] = struct{}{}
	}

	for _, r := range roomsA {
		if _, ok := roomSetB[r]; ok {
			return true, nil
		}
	}
	return false, nil
}
