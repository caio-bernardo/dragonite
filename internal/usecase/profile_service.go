package usecase

import (
	"context"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

type ProfileService struct {
	userStore  UsuarioStorage
	canalStore CanalStorage
}

func NewProfileService(userStore UsuarioStorage) *ProfileService {
	return &ProfileService{
		userStore: userStore,
	}
}

func (p *ProfileService) GetProfileByUserID(ctx context.Context, user_id string) (*domain.Profile, error) {
	if user_id == "" {
		return nil, types.ErrInvalidUserID
	}

	profile, err := p.userStore.GetProfileByID(ctx, user_id)
	if err != nil {
		return nil, types.ErrNotFound
	}
	if profile == nil {
    return nil, types.ErrNotFound
	}
	return profile, nil

}

type ProfileParams struct {
	DisplayName *string `json:"displayname,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
}

func (p *ProfileService) UpdateProfile(ctx context.Context, userID string, props ProfileParams) error {
	if userID == "" {
		return types.ErrInvalidUserID
	}

	profile := domain.Profile{
		IDUsuario:   userID,
		DisplayName: props.DisplayName,
		AvatarURL:   props.AvatarURL,
	}

	err := p.userStore.UpdateProfile(ctx, profile)
	if err != nil {
		return err
	}
	return nil
}
