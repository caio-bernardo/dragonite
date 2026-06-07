package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/util"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	jwtSecret   string
	ServerName  string
	userStore   UsuarioStorage
	deviceStore DeviceStorage
}

func NewAuthService(jwtSecret, serverName string, userStore UsuarioStorage, deviceStore DeviceStorage) *AuthService {
	return &AuthService{
		jwtSecret:   jwtSecret,
		ServerName:  serverName,
		userStore:   userStore,
		deviceStore: deviceStore,
	}
}

type LoginParams struct {
	Indentifier types.UserIndentifier
	Password    string
	DeviceID    string
	DeviceName  string
	DeviceIP    string
}

type LoginSuccess struct {
	AccessToken  string
	RefreshToken string
	ExpireMS     *int64
	UserID       string
	DeviceID     string
}

func (s *AuthService) Login(ctx context.Context, params LoginParams) (LoginSuccess, error) {
	if params.Indentifier.Type != types.IdentifierTypeUser {
		return LoginSuccess{}, types.ErrUnimplemented
	}

	user, err := s.userStore.GetUsuarioByID(ctx, params.Indentifier.User)
	if err != nil {
		return LoginSuccess{}, types.ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.SenhaHash), []byte(params.Password)); err != nil {
		return LoginSuccess{}, types.ErrInvalidCredentials
	}

	// Cria o token de refresh
	refreshToken, refreshExpires, err := util.GenerateRefreshToken()
	if err != nil {
		return LoginSuccess{}, types.InternalError(err)
	}

	// Cria ou atualiza o disposivo atual
	var deviceID uuid.UUID
	if params.DeviceID == "" {
		newID, err := uuid.NewV7()
		if err != nil {
			return LoginSuccess{}, types.InternalError(err)
		}
		deviceID = newID
	} else {
		var err error
		deviceID, err = uuid.Parse(params.DeviceID)
		if err != nil {
			return LoginSuccess{}, types.ErrInvalidCredentials
		}
	}
	device := domain.Dispositivo{
		ID:                    deviceID,
		Nome:                  params.DeviceName,
		UltimoIPVisto:         params.DeviceIP,
		UltimoTimestampVisto:  time.Now(),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpires,
		UsuarioID:             user.ID,
	}

	err = s.deviceStore.UpsertDispositivo(ctx, &device)
	if err != nil {
		return LoginSuccess{}, types.InternalError(err)
	}

	// cria os tokens de acesso
	accessToken, expiresMS, err := util.GenerateAccessToken(user.ID, device.ID.String(), s.jwtSecret, s.ServerName)
	if err != nil {
		return LoginSuccess{}, types.InternalError(err)
	}

	return LoginSuccess{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpireMS:     &expiresMS,
		UserID:       user.ID,
		DeviceID:     device.ID.String(),
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, userID, deviceID string) error {
	device, err := s.deviceStore.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}

	if device.UsuarioID != userID {
		return types.ErrUnauthorized
	}

	// invalida o token
	device.RefreshTokenExpiresAt = time.Now()
	if err := s.deviceStore.UpdateDevice(ctx, device); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (string, int64, error) {
	device, err := s.deviceStore.GetDispositivoByRefreshToken(ctx, refreshToken)
	if err != nil {
		return "", 0, types.InternalError(err)
	}

	if device.RefreshTokenExpiresAt.Before(time.Now()) {
		return "", 0, types.ErrUnauthorized
	}

	accessToken, expiresMS, err := util.GenerateAccessToken(device.UsuarioID, device.ID.String(), s.jwtSecret, s.ServerName)
	if err != nil {
		return "", 0, types.InternalError(err)
	}

	return accessToken, expiresMS, nil
}

type RegisterParams struct {
	Username string
	Senha    string
}

func (s *AuthService) Register(ctx context.Context, params RegisterParams) (string, error) {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(params.Senha), bcrypt.DefaultCost)
	if err != nil {
		return "", types.InternalError(err)
	}

	// cria um usuario, profile e AccountData
	userProps := domain.Usuario{
		LocalPart: params.Username,
		SenhaHash: hashedPassword,
	}

	usuario, err := s.userStore.CreateUsuarioAndProfile(ctx, userProps)
	if err != nil {
		if errors.Is(err, types.ErrAlreadyInUse) {
			return "", types.ErrAlreadyInUse
		}
		return "", types.InternalError(err)
	}
	return usuario.ID, nil
}
