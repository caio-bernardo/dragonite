package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/jackc/pgx/v5"
)

// UpsertCrossSigningKey insere ou substitui a chave de cross-signing do usuário para um uso
func (s *PostgresStorage) UpsertCrossSigningKey(ctx context.Context, key domain.ChaveCrossSigning) error {
	q := getTxOrPool(ctx, s.db)
	signatures := key.Signatures
	if len(signatures) == 0 {
		signatures = json.RawMessage(`{}`)
	}
	_, err := q.Exec(ctx, `
		INSERT INTO Chave_Cross_Signing (fk_id_usuario, key_usage, key_id, public_key, signatures)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (fk_id_usuario, key_usage) DO UPDATE SET
			key_id = $3, public_key = $4, signatures = $5
	`, key.UsuarioID, key.Usage, key.KeyID, []byte(key.Keys), []byte(signatures))
	if err != nil {
		return fmt.Errorf("failed to upsert cross-signing key (usage=%s): %w", key.Usage, err)
	}
	return nil
}

// GetCrossSigningKeys retorna as chaves de cross-signing de um usuário, indexadas por uso
func (s *PostgresStorage) GetCrossSigningKeys(ctx context.Context, userID string) (map[string]domain.ChaveCrossSigning, error) {
	q := getTxOrPool(ctx, s.db)
	rows, err := q.Query(ctx, `
		SELECT key_usage, key_id, public_key, signatures
		FROM Chave_Cross_Signing
		WHERE fk_id_usuario = $1
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cross-signing keys for user '%s': %w", userID, err)
	}
	defer rows.Close()

	result := make(map[string]domain.ChaveCrossSigning)
	for rows.Next() {
		var k domain.ChaveCrossSigning
		if err := rows.Scan(&k.Usage, &k.KeyID, &k.Keys, &k.Signatures); err != nil {
			return nil, fmt.Errorf("failed to scan cross-signing key: %w", err)
		}
		k.UsuarioID = userID
		result[k.Usage] = k
	}
	return result, rows.Err()
}

// MergeDeviceSignatures funde novas assinaturas nas já armazenadas de um dispositivo.
// Retorna false, nil se o dispositivo não existir (ou não tiver chaves de identidade cadastradas)
func (s *PostgresStorage) MergeDeviceSignatures(ctx context.Context, userID, deviceID string, newSignatures json.RawMessage) (bool, error) {
	q := getTxOrPool(ctx, s.db)

	row := q.QueryRow(ctx, `
		SELECT cd.signatures
		FROM Chave_Dispositivo cd
		JOIN Dispositivo d ON d.id = cd.fk_id_dispositivo
		WHERE d.fk_id_usuario = $1 AND d.id::text = $2
		FOR UPDATE
	`, userID, deviceID)

	var current json.RawMessage
	if err := row.Scan(&current); err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to read device signatures: %w", err)
	}

	merged, err := mergeSignatures(current, newSignatures)
	if err != nil {
		return false, fmt.Errorf("failed to merge device signatures: %w", err)
	}

	if _, err := q.Exec(ctx, `UPDATE Chave_Dispositivo SET signatures = $1 WHERE fk_id_dispositivo = $2`, merged, deviceID); err != nil {
		return false, fmt.Errorf("failed to persist merged device signatures: %w", err)
	}
	return true, nil
}

// MergeCrossSigningSignatures funde novas assinaturas nas já armazenadas de uma chave de cross-signing.
func (s *PostgresStorage) MergeCrossSigningSignatures(ctx context.Context, userID, publicKeyID string, newSignatures json.RawMessage) (bool, error) {
	q := getTxOrPool(ctx, s.db)

	row := q.QueryRow(ctx, `
		SELECT signatures FROM Chave_Cross_Signing
		WHERE fk_id_usuario = $1 AND key_id = $2
		FOR UPDATE
	`, userID, publicKeyID)

	var current json.RawMessage
	if err := row.Scan(&current); err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("failed to read cross-signing signatures: %w", err)
	}

	merged, err := mergeSignatures(current, newSignatures)
	if err != nil {
		return false, fmt.Errorf("failed to merge cross-signing signatures: %w", err)
	}

	if _, err := q.Exec(ctx, `UPDATE Chave_Cross_Signing SET signatures = $1 WHERE fk_id_usuario = $2 AND key_id = $3`, merged, userID, publicKeyID); err != nil {
		return false, fmt.Errorf("failed to persist merged cross-signing signatures: %w", err)
	}
	return true, nil
}

// mergeSignatures funde duas árvores de assinaturas no formato {userID: {keyID: signature}},
// dando prioridade às novas assinaturas em caso de conflito de chave
func mergeSignatures(current, incoming json.RawMessage) (json.RawMessage, error) {
	merged := make(map[string]map[string]json.RawMessage)
	if len(current) > 0 {
		if err := json.Unmarshal(current, &merged); err != nil {
			return nil, err
		}
	}
	var incomingMap map[string]map[string]json.RawMessage
	if len(incoming) > 0 {
		if err := json.Unmarshal(incoming, &incomingMap); err != nil {
			return nil, err
		}
	}
	for signerUser, sigs := range incomingMap {
		if merged[signerUser] == nil {
			merged[signerUser] = make(map[string]json.RawMessage)
		}
		for keyID, sig := range sigs {
			merged[signerUser][keyID] = sig
		}
	}
	return json.Marshal(merged)
}
