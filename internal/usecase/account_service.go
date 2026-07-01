package usecase

import (
	"context"
	"encoding/json"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

// AccountService handles account_data usecases
type AccountService struct {
	userStore UsuarioStorage
}

func NewAccountService(userStore UsuarioStorage) *AccountService {
	return &AccountService{userStore: userStore}
}

// PutUserAccountData saves account data for a user (user-scoped or room-scoped)
func (s *AccountService) PutUserAccountData(ctx context.Context, userID, roomID, tipo string, content json.RawMessage) error {
	if userID == "" {
		return types.ErrInvalidUserID
	}
	if tipo == "" {
		return types.ErrInvalidParam
	}

	acct := domain.AccountData{
		IDUsuario: userID,
		IDCanal:   roomID,
		Tipo:      tipo,
		Content:   content,
	}

	return s.userStore.SaveAccountData(ctx, acct)
}

// GetUserAccountData retrieves account data for a user
func (s *AccountService) GetUserAccountData(ctx context.Context, userID, roomID, tipo string) (*domain.AccountData, error) {
	if userID == "" {
		return nil, types.ErrInvalidUserID
	}
	if tipo == "" {
		return nil, types.ErrInvalidParam
	}

	return s.userStore.GetAccountData(ctx, userID, roomID, tipo)
}
