package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/caio-bernardo/dragonite/internal/domain"
)

// ErrBackupNotFound é retornado quando o usuário nunca criou uma versão de backup
var ErrBackupNotFound = errors.New("no backup version found")

// BackupService contém a lógica para as versões de backup de chaves (E2EE room_keys)
type BackupService struct {
	uow           WorkUnit
	backupStorage BackupStorage
}

func NewBackupService(uow WorkUnit, backupStorage BackupStorage) *BackupService {
	return &BackupService{uow: uow, backupStorage: backupStorage}
}

// CreateBackupParams contém os dados necessários para criar uma nova versão de backup
type CreateBackupParams struct {
	UserID    string
	Algorithm string
	AuthData  json.RawMessage
}

// CreateBackupVersion cria uma nova versão de backup para o usuário
// Uma versão nova NÃO apaga versões anteriores, só passa a ser a "latest"
func (s *BackupService) CreateBackupVersion(ctx context.Context, params CreateBackupParams) (*domain.VersaoBackup, error) {
	backup := &domain.VersaoBackup{
		IDUsuario: params.UserID,
		Algorithm: params.Algorithm,
		AuthData:  params.AuthData,
		Count:     0,
		ETag:      "0",
	}

	if err := s.backupStorage.CreateBackupVersion(ctx, backup); err != nil {
		return nil, fmt.Errorf("failed to create backup version: %w", err)
	}

	return backup, nil
}

// GetLatestBackupVersion retorna a versão de backup mais recente do usuário
func (s *BackupService) GetLatestBackupVersion(ctx context.Context, userID string) (*domain.VersaoBackup, error) {
	backup, err := s.backupStorage.GetLatestBackupVersion(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest backup version: %w", err)
	}
	if backup == nil {
		return nil, ErrBackupNotFound
	}

	return backup, nil
}

// ErrWrongVersion é retornado quando a versão informada em PUT room_keys/keys
// não é a versão atual (latest) do backup do usuário
type ErrWrongVersion struct {
	CurrentVersion string
}

func (e *ErrWrongVersion) Error() string {
	return fmt.Sprintf("wrong backup version, current is %s", e.CurrentVersion)
}

// parseVersion converte o identificador de versão (string opaca) para o id interno
func parseVersion(version string) (int64, error) {
	return strconv.ParseInt(version, 10, 64)
}

// GetRoomKeys retorna as chaves armazenadas numa versão de backup específica do usuário
func (s *BackupService) GetRoomKeys(ctx context.Context, userID, version string) ([]domain.ChaveBackup, error) {
	versionID, err := parseVersion(version)
	if err != nil {
		return nil, ErrBackupNotFound
	}

	backup, err := s.backupStorage.GetBackupVersionByID(ctx, userID, versionID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch backup version: %w", err)
	}
	if backup == nil {
		return nil, ErrBackupNotFound
	}

	keys, err := s.backupStorage.GetRoomKeys(ctx, versionID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch room keys: %w", err)
	}

	return keys, nil
}

// PutRoomKeysParams contém os dados necessários para armazenar chaves no backup
type PutRoomKeysParams struct {
	UserID  string
	Version string
	Keys    []domain.ChaveBackup
}

// PutRoomKeys armazena chaves de salas na versão de backup especificada do usuário
func (s *BackupService) PutRoomKeys(ctx context.Context, params PutRoomKeysParams) (count int64, etag string, err error) {
	versionID, err := parseVersion(params.Version)
	if err != nil {
		return 0, "", ErrBackupNotFound
	}

	// validação fora da transação
	latest, err := s.backupStorage.GetLatestBackupVersion(ctx, params.UserID)
	if err != nil {
		return 0, "", fmt.Errorf("failed to fetch latest backup version: %w", err)
	}
	if latest == nil {
		return 0, "", ErrBackupNotFound
	}
	if latest.IDVersao != versionID {
		backup, err := s.backupStorage.GetBackupVersionByID(ctx, params.UserID, versionID)
		if err != nil {
			return 0, "", fmt.Errorf("failed to fetch backup version: %w", err)
		}
		if backup == nil {
			return 0, "", ErrBackupNotFound
		}
		return 0, "", &ErrWrongVersion{CurrentVersion: latest.VersionString()}
	}

	for i := range params.Keys {
		params.Keys[i].IDVersao = versionID
	}

	// escrita transacional: upsert das chaves + update de count/etag são atômicos
	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
		var txErr error
		count, etag, txErr = s.backupStorage.PutRoomKeys(txCtx, versionID, params.Keys)
		return txErr
	})
	if err != nil {
		return 0, "", fmt.Errorf("failed to store room keys: %w", err)
	}

	return count, etag, nil
}

// DeleteRoomKeys apaga todas as chaves armazenadas numa versão de backup específica do usuário
func (s *BackupService) DeleteRoomKeys(ctx context.Context, userID, version string) (count int64, etag string, err error) {
	versionID, err := parseVersion(version)
	if err != nil {
		return 0, "", ErrBackupNotFound
	}

	backup, err := s.backupStorage.GetBackupVersionByID(ctx, userID, versionID)
	if err != nil {
		return 0, "", fmt.Errorf("failed to fetch backup version: %w", err)
	}
	if backup == nil {
		return 0, "", ErrBackupNotFound
	}

	err = s.uow.Execute(ctx, func(txCtx context.Context) error {
		var txErr error
		count, etag, txErr = s.backupStorage.DeleteRoomKeys(txCtx, versionID)
		return txErr
	})
	if err != nil {
		return 0, "", fmt.Errorf("failed to delete room keys: %w", err)
	}

	return count, etag, nil
}
