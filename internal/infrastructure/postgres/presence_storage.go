package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/jackc/pgx/v5"
)

// UpsertPresence insere ou atualiza o estado de presença de um usuário
func (s *PostgresStorage) UpsertPresence(ctx context.Context, presence domain.Presence) error {
	db := getTxOrPool(ctx, s.db)
	_, err := db.Exec(ctx, `
		INSERT INTO Presence (id_usuario, presence_state, status_msg, last_active_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id_usuario) DO UPDATE
		SET presence_state = $2, status_msg = $3, last_active_at = $4
	`, presence.IDUsuario, string(presence.State), presence.StatusMsg, presence.LastActiveAt)
	if err != nil {
		return fmt.Errorf("failed to upsert presence: %w", err)
	}
	return nil
}

// GetPresence recupera o estado de presença atual de um usuário
// Retorna (nil, nil) se o usuário nunca teve presence definida
func (s *PostgresStorage) GetPresence(ctx context.Context, userID string) (*domain.Presence, error) {
	db := getTxOrPool(ctx, s.db)
	row := db.QueryRow(ctx,
		"SELECT id_usuario, presence_state, status_msg, last_active_at FROM Presence WHERE id_usuario = $1",
		userID)

	var presence domain.Presence
	var state string
	err := row.Scan(&presence.IDUsuario, &state, &presence.StatusMsg, &presence.LastActiveAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get presence: %w", err)
	}
	presence.State = domain.PresenceState(state)

	return &presence, nil
}
