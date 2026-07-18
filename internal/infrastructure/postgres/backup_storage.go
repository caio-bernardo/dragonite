package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/jackc/pgx/v5"
)

// CreateBackupVersion insere uma nova versão de backup de chaves para o usuário
func (s *PostgresStorage) CreateBackupVersion(ctx context.Context, backup *domain.VersaoBackup) error {
	row := s.db.QueryRow(ctx, `
		INSERT INTO VersaoBackup (id_usuario, algorithm, auth_data, count, etag)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id_versao, created_at
	`, backup.IDUsuario, backup.Algorithm, backup.AuthData, backup.Count, backup.ETag)

	if err := row.Scan(&backup.IDVersao, &backup.CreatedAt); err != nil {
		return fmt.Errorf("failure to create backup version for user '%s': %w", backup.IDUsuario, err)
	}

	return nil
}

// GetLatestBackupVersion recupera a versão de backup mais recente (maior id_versao) do usuário
// Retorna (nil, nil) se o usuário nunca criou um backup
func (s *PostgresStorage) GetLatestBackupVersion(ctx context.Context, userID string) (*domain.VersaoBackup, error) {
	row := s.db.QueryRow(ctx, `
		SELECT id_versao, id_usuario, algorithm, auth_data, count, etag, created_at
		FROM VersaoBackup
		WHERE id_usuario = $1
		ORDER BY id_versao DESC
		LIMIT 1
	`, userID)

	var backup domain.VersaoBackup
	err := row.Scan(
		&backup.IDVersao,
		&backup.IDUsuario,
		&backup.Algorithm,
		&backup.AuthData,
		&backup.Count,
		&backup.ETag,
		&backup.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch latest backup version for user '%s': %w", userID, err)
	}

	return &backup, nil
}

func (s *PostgresStorage) GetBackupVersionByID(ctx context.Context, userID string, versionID int64) (*domain.VersaoBackup, error) {
	q := getTxOrPool(ctx, s.db)
	row := q.QueryRow(ctx, `
		SELECT id_versao, id_usuario, algorithm, auth_data, count, etag, created_at
		FROM VersaoBackup
		WHERE id_usuario = $1 AND id_versao = $2
	`, userID, versionID)

	var backup domain.VersaoBackup
	err := row.Scan(
		&backup.IDVersao, &backup.IDUsuario, &backup.Algorithm,
		&backup.AuthData, &backup.Count, &backup.ETag, &backup.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch backup version %d for user '%s': %w", versionID, userID, err)
	}

	return &backup, nil
}

func (s *PostgresStorage) GetRoomKeys(ctx context.Context, versionID int64) ([]domain.ChaveBackup, error) {
	q := getTxOrPool(ctx, s.db)
	rows, err := q.Query(ctx, `
		SELECT id_versao, id_canal, id_sessao, first_message_index, forwarded_count, is_verified, session_data
		FROM ChaveBackup
		WHERE id_versao = $1
	`, versionID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch room keys for version %d: %w", versionID, err)
	}
	defer rows.Close()

	var keys []domain.ChaveBackup
	for rows.Next() {
		var k domain.ChaveBackup
		if err := rows.Scan(
			&k.IDVersao, &k.IDCanal, &k.IDSessao,
			&k.FirstMessageIndex, &k.ForwardedCount, &k.IsVerified, &k.SessionData,
		); err != nil {
			return nil, fmt.Errorf("failed to scan room key: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate room keys: %w", err)
	}

	return keys, nil
}

// PutRoomKeys usa getTxOrPool para participar da transação aberta por BackupService.PutRoomKeys
// via WorkUnit, o upsert das chaves e o update de count/etag são atômicos
func (s *PostgresStorage) PutRoomKeys(ctx context.Context, versionID int64, keys []domain.ChaveBackup) (int64, string, error) {
	q := getTxOrPool(ctx, s.db)

	for _, k := range keys {
		_, err := q.Exec(ctx, `
			INSERT INTO ChaveBackup (id_versao, id_canal, id_sessao, first_message_index, forwarded_count, is_verified, session_data)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id_versao, id_canal, id_sessao) DO UPDATE SET
				first_message_index = EXCLUDED.first_message_index,
				forwarded_count = EXCLUDED.forwarded_count,
				is_verified = EXCLUDED.is_verified,
				session_data = EXCLUDED.session_data
		`, versionID, k.IDCanal, k.IDSessao, k.FirstMessageIndex, k.ForwardedCount, k.IsVerified, k.SessionData)
		if err != nil {
			return 0, "", fmt.Errorf("failed to upsert room key (room=%s, session=%s): %w", k.IDCanal, k.IDSessao, err)
		}
	}

	row := q.QueryRow(ctx, `
		WITH contagem AS (
			SELECT COUNT(*) AS total FROM ChaveBackup WHERE id_versao = $1
		)
		UPDATE VersaoBackup
		SET count = contagem.total, etag = (VersaoBackup.etag::bigint + 1)::text
		FROM contagem
		WHERE id_versao = $1
		RETURNING VersaoBackup.count, VersaoBackup.etag
	`, versionID)

	var count int64
	var etag string
	if err := row.Scan(&count, &etag); err != nil {
		return 0, "", fmt.Errorf("failed to update backup version %d after put: %w", versionID, err)
	}

	return count, etag, nil
}

// DeleteRoomKeys participa da transação via getTxOrPool
func (s *PostgresStorage) DeleteRoomKeys(ctx context.Context, versionID int64) (int64, string, error) {
	q := getTxOrPool(ctx, s.db)

	if _, err := q.Exec(ctx, `DELETE FROM ChaveBackup WHERE id_versao = $1`, versionID); err != nil {
		return 0, "", fmt.Errorf("failed to delete room keys for version %d: %w", versionID, err)
	}

	row := q.QueryRow(ctx, `
		UPDATE VersaoBackup
		SET count = 0, etag = (etag::bigint + 1)::text
		WHERE id_versao = $1
		RETURNING etag
	`, versionID)

	var etag string
	if err := row.Scan(&etag); err != nil {
		return 0, "", fmt.Errorf("failed to update backup version %d after delete: %w", versionID, err)
	}

	return 0, etag, nil
}
