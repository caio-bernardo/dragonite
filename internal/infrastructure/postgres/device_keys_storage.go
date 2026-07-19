package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/jackc/pgx/v5"
)

// UpsertDeviceKeys insere ou substitui as chaves de identidade de um dispositivo
func (s *PostgresStorage) UpsertDeviceKeys(ctx context.Context, keys domain.ChavesDispositivo) error {
	q := getTxOrPool(ctx, s.db)
	_, err := q.Exec(ctx, `
		INSERT INTO Chave_Dispositivo (fk_id_dispositivo, algorithms, device_keys, signatures)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (fk_id_dispositivo) DO UPDATE SET
			algorithms = $2, device_keys = $3, signatures = $4, updated_at = CURRENT_TIMESTAMP
	`, keys.DispositivoID, keys.Algorithms, []byte(keys.Keys), []byte(keys.Signatures))
	if err != nil {
		return fmt.Errorf("failed to upsert device keys: %w", err)
	}
	return nil
}

// GetDeviceKeys retorna as chaves de identidade dos dispositivos indicados de um usuário
// Se deviceIDs for vazio, retorna as chaves de todos os dispositivos do usuário
func (s *PostgresStorage) GetDeviceKeys(ctx context.Context, userID string, deviceIDs []string) ([]domain.ChavesDispositivo, error) {
	q := getTxOrPool(ctx, s.db)

	var rows pgx.Rows
	var err error
	if len(deviceIDs) == 0 {
		rows, err = q.Query(ctx, `
			SELECT d.id::text, cd.algorithms, cd.device_keys, cd.signatures, d.nome
			FROM Dispositivo d
			JOIN Chave_Dispositivo cd ON cd.fk_id_dispositivo = d.id
			WHERE d.fk_id_usuario = $1
		`, userID)
	} else {
		rows, err = q.Query(ctx, `
			SELECT d.id::text, cd.algorithms, cd.device_keys, cd.signatures, d.nome
			FROM Dispositivo d
			JOIN Chave_Dispositivo cd ON cd.fk_id_dispositivo = d.id
			WHERE d.fk_id_usuario = $1 AND d.id::text = ANY($2)
		`, userID, deviceIDs)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query device keys for user '%s': %w", userID, err)
	}
	defer rows.Close()

	var result []domain.ChavesDispositivo
	for rows.Next() {
		var k domain.ChavesDispositivo
		var deviceID, nome string
		if err := rows.Scan(&deviceID, &k.Algorithms, &k.Keys, &k.Signatures, &nome); err != nil {
			return nil, fmt.Errorf("failed to scan device keys row: %w", err)
		}
		k.DispositivoID = deviceID
		k.UsuarioID = userID
		k.NomeDispositivo = nome
		result = append(result, k)
	}
	return result, rows.Err()
}

// UpsertOneTimeKeys insere novas one-time keys de um dispositivo, ignorando as que já existirem (idempotente por key_id)
func (s *PostgresStorage) UpsertOneTimeKeys(ctx context.Context, deviceID string, keys []domain.ChaveUsoUnico) error {
	q := getTxOrPool(ctx, s.db)
	for _, k := range keys {
		_, err := q.Exec(ctx, `
			INSERT INTO Chave_Uso_Unico (fk_id_dispositivo, key_id, algorithm, key_data)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (fk_id_dispositivo, key_id) DO NOTHING
		`, deviceID, k.KeyID, k.Algorithm, []byte(k.KeyData))
		if err != nil {
			return fmt.Errorf("failed to insert one-time key %s: %w", k.KeyID, err)
		}
	}
	return nil
}

// ClaimOneTimeKey reivindica (e apaga) UMA one-time key de um dispositivo para o algoritmo pedido,
// na ordem em que foram enviadas (garante que a mesma chave nunca é devolvida duas vezes)
func (s *PostgresStorage) ClaimOneTimeKey(ctx context.Context, deviceID, algorithm string) (*domain.ChaveUsoUnico, error) {
	q := getTxOrPool(ctx, s.db)
	row := q.QueryRow(ctx, `
		DELETE FROM Chave_Uso_Unico
		WHERE id = (
		    SELECT id FROM Chave_Uso_Unico
		    WHERE fk_id_dispositivo = $1 AND algorithm = $2
		    ORDER BY id ASC
		    LIMIT 1
		    FOR UPDATE SKIP LOCKED
		)
		RETURNING key_id, key_data
	`, deviceID, algorithm)

	var k domain.ChaveUsoUnico
	err := row.Scan(&k.KeyID, &k.KeyData)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to claim one-time key: %w", err)
	}
	k.DispositivoID = deviceID
	k.Algorithm = algorithm
	return &k, nil
}

// CountOneTimeKeys conta as one-time keys remanescentes de um dispositivo, agrupadas por algoritmo
func (s *PostgresStorage) CountOneTimeKeys(ctx context.Context, deviceID string) (map[string]int, error) {
	q := getTxOrPool(ctx, s.db)
	rows, err := q.Query(ctx, `
		SELECT algorithm, COUNT(*) FROM Chave_Uso_Unico WHERE fk_id_dispositivo = $1 GROUP BY algorithm
	`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to count one-time keys: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var algorithm string
		var count int
		if err := rows.Scan(&algorithm, &count); err != nil {
			return nil, fmt.Errorf("failed to scan one-time key count: %w", err)
		}
		counts[algorithm] = count
	}
	return counts, rows.Err()
}

// UpsertFallbackKey insere ou substitui a fallback key de um dispositivo para um algoritmo, marcando-a como não usada
func (s *PostgresStorage) UpsertFallbackKey(ctx context.Context, key domain.ChaveFallback) error {
	q := getTxOrPool(ctx, s.db)
	_, err := q.Exec(ctx, `
		INSERT INTO Chave_Fallback (fk_id_dispositivo, algorithm, key_id, key_data, usada)
		VALUES ($1, $2, $3, $4, FALSE)
		ON CONFLICT (fk_id_dispositivo, algorithm) DO UPDATE SET key_id = $3, key_data = $4, usada = FALSE
	`, key.DispositivoID, key.Algorithm, key.KeyID, []byte(key.KeyData))
	if err != nil {
		return fmt.Errorf("failed to upsert fallback key: %w", err)
	}
	return nil
}

// ClaimFallbackKey retorna a fallback key de um dispositivo para o algoritmo pedido e a marca como usada
// Retorna nil, nil se o dispositivo não tiver fallback key cadastrada para o algoritmo
func (s *PostgresStorage) ClaimFallbackKey(ctx context.Context, deviceID, algorithm string) (*domain.ChaveFallback, error) {
	q := getTxOrPool(ctx, s.db)
	row := q.QueryRow(ctx, `
		UPDATE Chave_Fallback SET usada = TRUE
		WHERE fk_id_dispositivo = $1 AND algorithm = $2
		RETURNING key_id, key_data, usada
	`, deviceID, algorithm)

	var k domain.ChaveFallback
	err := row.Scan(&k.KeyID, &k.KeyData, &k.Usada)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to claim fallback key: %w", err)
	}
	k.DispositivoID = deviceID
	k.Algorithm = algorithm
	return &k, nil
}
