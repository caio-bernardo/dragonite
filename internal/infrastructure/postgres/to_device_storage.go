package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
)

// InsertToDeviceMessages insere mensagens pendentes em lote (uma por dispositivo destinatário)
func (s *PostgresStorage) InsertToDeviceMessages(ctx context.Context, messages []domain.ToDeviceMessage) error {
	q := getTxOrPool(ctx, s.db)
	for _, m := range messages {
		_, err := q.Exec(ctx, `
			INSERT INTO Mensagem_ToDevice (fk_id_usuario, fk_id_dispositivo, remetente, tipo, content)
			VALUES ($1, $2::uuid, $3, $4, $5)
		`, m.UserID, m.DeviceID, m.Sender, m.Type, []byte(m.Content))
		if err != nil {
			return fmt.Errorf("failed to insert to-device message (user=%s device=%s): %w", m.UserID, m.DeviceID, err)
		}
	}
	return nil
}

// GetToDeviceMessagesSince retorna até `limit` mensagens pendentes de um dispositivo com id > since
func (s *PostgresStorage) GetToDeviceMessagesSince(ctx context.Context, userID, deviceID string, since int64, limit int) ([]domain.ToDeviceMessage, error) {
	q := getTxOrPool(ctx, s.db)
	rows, err := q.Query(ctx, `
		SELECT id, fk_id_usuario, fk_id_dispositivo, remetente, tipo, content
		FROM Mensagem_ToDevice
		WHERE fk_id_usuario = $1 AND fk_id_dispositivo = $2::uuid AND id > $3
		ORDER BY id ASC
		LIMIT $4
	`, userID, deviceID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to-device messages (user=%s device=%s): %w", userID, deviceID, err)
	}
	defer rows.Close()

	var result []domain.ToDeviceMessage
	for rows.Next() {
		var m domain.ToDeviceMessage
		if err := rows.Scan(&m.ID, &m.UserID, &m.DeviceID, &m.Sender, &m.Type, &m.Content); err != nil {
			return nil, fmt.Errorf("failed to scan to-device message: %w", err)
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// DeleteToDeviceMessagesUpTo apaga as mensagens já entregues (id <= upTo) de um dispositivo
func (s *PostgresStorage) DeleteToDeviceMessagesUpTo(ctx context.Context, userID, deviceID string, upTo int64) error {
	q := getTxOrPool(ctx, s.db)
	_, err := q.Exec(ctx, `
		DELETE FROM Mensagem_ToDevice
		WHERE fk_id_usuario = $1 AND fk_id_dispositivo = $2::uuid AND id <= $3
	`, userID, deviceID, upTo)
	if err != nil {
		return fmt.Errorf("failed to delete delivered to-device messages (user=%s device=%s): %w", userID, deviceID, err)
	}
	return nil
}
