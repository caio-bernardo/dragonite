package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/jackc/pgx/v5"
)

func (s *PostgresStorage) GetDeviceByID(ctx context.Context, deviceID string) (*domain.Dispositivo, error) {
	row := s.db.QueryRow(ctx,
		"SELECT id, fk_id_usuario, nome, refresh_token, refresh_token_expires_at, ultimo_ip_visto, ultimo_timestamp_visto FROM Dispositivo WHERE id = $1",
		deviceID)

	var device domain.Dispositivo
	err := row.Scan(&device.ID, &device.UsuarioID, &device.Nome, &device.RefreshToken, &device.RefreshTokenExpiresAt, &device.UltimoIPVisto, &device.UltimoTimestampVisto)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	return &device, nil
}

func (s *PostgresStorage) GetDispositivoByRefreshToken(ctx context.Context, refreshToken string) (*domain.Dispositivo, error) {
	row := s.db.QueryRow(ctx,
		"SELECT id, fk_id_usuario, nome, refresh_token, refresh_token_expires_at, ultimo_ip_visto, ultimo_timestamp_visto FROM Dispositivo WHERE refresh_token = $1",
		refreshToken)

	var device domain.Dispositivo
	err := row.Scan(&device.ID, &device.UsuarioID, &device.Nome, &device.RefreshToken, &device.RefreshTokenExpiresAt, &device.UltimoIPVisto, &device.UltimoTimestampVisto)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get device by refresh token: %w", err)
	}

	return &device, nil
}

func (s *PostgresStorage) UpsertDispositivo(ctx context.Context, device *domain.Dispositivo) error {
	_, err := s.db.Exec(ctx,
		"INSERT INTO Dispositivo (id, fk_id_usuario, nome, refresh_token, refresh_token_expires_at, ultimo_ip_visto, ultimo_timestamp_visto) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO UPDATE SET nome = $3, refresh_token = $4, refresh_token_expires_at = $5, ultimo_ip_visto = $6, ultimo_timestamp_visto = $7",
		device.ID, device.UsuarioID, device.Nome, device.RefreshToken, device.RefreshTokenExpiresAt, device.UltimoIPVisto, device.UltimoTimestampVisto)
	if err != nil {
		return fmt.Errorf("failed to upsert device: %w", err)
	}

	return nil
}

func (s *PostgresStorage) UpdateDevice(ctx context.Context, device *domain.Dispositivo) error {
	_, err := s.db.Exec(ctx,
		"UPDATE Dispositivo SET nome = $1, refresh_token = $2, refresh_token_expires_at = $3, ultimo_ip_visto = $4, ultimo_timestamp_visto = $5 WHERE id = $6",
		device.Nome, device.RefreshToken, device.RefreshTokenExpiresAt, device.UltimoIPVisto, device.UltimoTimestampVisto, device.ID)
	if err != nil {
		return fmt.Errorf("failed to update device: %w", err)
	}

	return nil
}
