package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/lib/pq"
)

func (s *PostgresStorage) GetSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error) {
	rows, err := s.db.Query(ctx,
		"SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, stream_ordering, state_key FROM Evento WHERE stream_ordering > $1 ORDER BY stream_ordering ASC",
		since.TimelinePosition)
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}
	defer rows.Close()

	var eventos []domain.Evento
	for rows.Next() {
		var event domain.Evento
		var stateKey sql.NullString
		err := rows.Scan(&event.ID, &event.Tipo, &event.CanalID, &event.Sender, &event.OrigemServidorTS, &event.Content, &event.StreamOrdering, &stateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		if stateKey.Valid {
			event.StateKey = &stateKey.String
		}
		eventos = append(eventos, event)
	}

	return eventos, nil
}

func (s *PostgresStorage) GetMaxDepthFromEventos(ctx context.Context, prevEventos []string) (int64, error) {
	if len(prevEventos) == 0 {
		return 0, nil
	}

	query := `SELECT COALESCE(MAX(depth), 0) FROM Evento WHERE id_evento = ANY($1)`
	var maxDepth int64
	err := s.db.QueryRow(ctx, query, pq.Array(prevEventos)).Scan(&maxDepth)
	if err != nil {
		return 0, fmt.Errorf("failed to get max depth: %w", err)
	}
	return maxDepth, nil
}

func (s *PostgresStorage) SaveEvento(ctx context.Context, event *domain.Evento) error {
	// NOTE: eventos de estado precisam ser atualizados caso enviados novamente
	_, err := s.db.Exec(ctx,
		`INSERT INTO Evento (id_evento, tipo, id_canal, sender, origin_server_ts, content, state_key, prev_eventos, auth_eventos, depth)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (id_evento) DO NOTHING`,
		event.ID, event.Tipo, event.CanalID, event.Sender, event.OrigemServidorTS, event.Content, event.StateKey, pq.Array(event.PrevEventos), pq.Array(event.AuthEventos), event.Depth)
	if err != nil {
		return fmt.Errorf("failed to save event: %w", err)
	}

	return nil
}
