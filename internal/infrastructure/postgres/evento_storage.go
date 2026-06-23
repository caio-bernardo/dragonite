package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/lib/pq"
)

func (s *PostgresStorage) GetSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error) {
	// Todos os eventos de canais os quais o usuário pertence + eventos sobre o próprio usuário
	query := `
		SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, stream_ordering, state_key
		FROM Evento
		WHERE stream_ordering > $2 AND (
			id_canal IN (
				SELECT id_canal FROM Canal_Membership
				WHERE id_usuario = $1 AND membership_type IN ('join', 'invite')
			)
			OR
			(tipo = 'm.room.member' AND state_key = $1)
		)
		ORDER BY stream_ordering ASC
	`
	rows, err := s.db.Query(ctx, query, userID, since.TimelinePosition)
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
	db := getTxOrPool(ctx, s.db)
	_, err := db.Exec(ctx,
		`INSERT INTO Evento (id_evento, tipo, id_canal, sender, origin_server_ts, content, state_key, prev_eventos, auth_eventos, depth)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (id_evento) DO NOTHING`,
		event.ID, event.Tipo, event.CanalID, event.Sender, event.OrigemServidorTS, event.Content, event.StateKey, pq.Array(event.PrevEventos), pq.Array(event.AuthEventos), event.Depth)
	if err != nil {
		return fmt.Errorf("failed to save event: %w", err)
	}

	return nil
}

func (s *PostgresStorage) CheckEventoExists(ctx context.Context, eventID string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM Evento WHERE id_evento = $1)`, eventID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check event exists: %w", err)
	}
	return exists, nil
}

func (s *PostgresStorage) GetEventsSince(ctx context.Context, roomID string, limit int, events []string) ([]domain.Evento, error) {
	query := `
	    WITH RECURSIVE dag_backfill AS (
			SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, stream_ordering, state_key, prev_eventos, auth_eventos, depth, 1 AS distance
			FROM Evento
			WHERE id_canal = $1 AND id_evento = ANY($2)

			UNION

			SELECT e.id_evento, e.tipo, e.id_canal, e.sender, e.origin_server_ts, e.content, e.stream_ordering, e.state_key, e.prev_eventos, e.auth_eventos, e.depth, db.distance + 1
			FROM Evento e
			JOIN dag_backfill db ON e.id_evento = ANY(db.prev_eventos)
			WHERE db.distance < $3
		)
		SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, stream_ordering, state_key
		FROM Evento
		ORDER BY depth DESC, distance ASC
		LIMIT $3;
	`
	rows, err := s.db.Query(ctx, query, roomID, pq.Array(events), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}
	defer rows.Close()

	var eventos []domain.Evento
	for rows.Next() {
		var event domain.Evento
		var stateKey sql.NullString
		err := rows.Scan(&event.ID, &event.Tipo, &event.CanalID, &event.Sender, &event.OrigemServidorTS, &event.Content, &event.StreamOrdering, &stateKey, &event.PrevEventos, &event.AuthEventos, &event.Depth)
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

func (s *PostgresStorage) GetEvento(ctx context.Context, eventID string) (*domain.Evento, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, state_key, prev_eventos, auth_eventos, depth FROM Evento WHERE id_evento = $1`,
		eventID,
	)
	var event domain.Evento
	var stateKey sql.NullString
	err := row.Scan(&event.ID, &event.Tipo, &event.CanalID, &event.Sender, &event.OrigemServidorTS, &event.Content, &stateKey, &event.PrevEventos, &event.AuthEventos, &event.Depth)
	if err != nil {
		return nil, fmt.Errorf("failed to scan event: %w", err)
	}
	if stateKey.Valid {
		event.StateKey = &stateKey.String
	}
	return &event, nil
}
