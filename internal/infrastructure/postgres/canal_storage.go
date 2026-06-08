package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/jackc/pgx/v5"
)

func (s *PostgresStorage) Create(ctx context.Context, roomID, userID string) (*domain.Canal, error) {
	row := s.db.QueryRow(ctx,
		"INSERT INTO Canal (id_canal, versao_canal, criador, created_at) VALUES ($1, $2, $3, CURRENT_TIMESTAMP) RETURNING id_canal, versao_canal, criador, created_at",
		roomID, "11", userID)

	var canal domain.Canal
	err := row.Scan(&canal.ID, &canal.Versao, &canal.Criador, &canal.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create canal: %w", err)
	}
	// TODO: criar ESTADO ATUAL

	return &canal, nil
}

func (s *PostgresStorage) GetByID(ctx context.Context, canalID string) (*domain.Canal, error) {
	row := s.db.QueryRow(ctx,
		"SELECT id_canal, versao_canal, criador, created_at FROM Canal WHERE id_canal = $1",
		canalID)

	var canal domain.Canal
	err := row.Scan(&canal.ID, &canal.Versao, &canal.Criador, &canal.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get canal: %w", err)
	}

	extremeties, err := s.GetForwardExtremities(ctx, canalID)
	if err == nil {
		canal.ForwardExtremeties = extremeties
	}
	// TODO: fill Canal.EstadoAtual

	return &canal, nil
}

func (s *PostgresStorage) GetJoinRule(ctx context.Context, roomID string) (string, error) {
	row := s.db.QueryRow(ctx,
		"SELECT id_evento FROM Canal_Estado_Atual WHERE id_canal = $1 AND tipo = 'm.room.join_rules' LIMIT 1",
		roomID)

	var eventID string
	err := row.Scan(&eventID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "invite", nil
		}
		return "", fmt.Errorf("failed to get join rule: %w", err)
	}

	return eventID, nil
}

func (s *PostgresStorage) GetUserJoinedRooms(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.Query(ctx,
		"SELECT id_canal FROM Canal_Membership WHERE id_usuario = $1 AND membership_type = 'join'",
		userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get joined rooms: %w", err)
	}
	defer rows.Close()

	var roomIDs []string
	for rows.Next() {
		var roomID string
		if err := rows.Scan(&roomID); err != nil {
			return nil, fmt.Errorf("failed to scan room id: %w", err)
		}
		roomIDs = append(roomIDs, roomID)
	}

	return roomIDs, nil
}

func (s *PostgresStorage) GetUserMembership(ctx context.Context, userID, roomID string) (string, error) {
	row := s.db.QueryRow(ctx,
		"SELECT membership_type FROM Canal_Membership WHERE id_usuario = $1 AND id_canal = $2",
		userID, roomID)

	var membership string
	err := row.Scan(&membership)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "leave", nil
		}
		return "", fmt.Errorf("failed to get membership: %w", err)
	}

	return membership, nil
}

func (s *PostgresStorage) GetStateEventID(ctx context.Context, canalID string, stateType, stateKey string) (string, bool) {
	row := s.db.QueryRow(ctx,
		"SELECT id_evento FROM Canal_Estado_Atual WHERE id_canal = $1 AND tipo = $2 AND state_key = $3",
		canalID, stateType, stateKey)

	var eventID string
	err := row.Scan(&eventID)
	if err != nil {
		return "", false
	}

	return eventID, true
}

func (s *PostgresStorage) UpsertMembership(ctx context.Context, userID, roomID, membership string) error {
	// TODO: id_evento do upsert está vazio
	_, err := s.db.Exec(ctx,
		"INSERT INTO Canal_Membership (id_canal, id_usuario, membership_type, id_evento) VALUES ($1, $2, $3, '') ON CONFLICT (id_canal, id_usuario) DO UPDATE SET membership_type = $3",
		roomID, userID, membership)
	if err != nil {
		return fmt.Errorf("failed to upsert membership: %w", err)
	}

	return nil
}

func (s *PostgresStorage) UpsertCurrentState(ctx context.Context, canalID, stateType, stateKey, eventID string) error {
	_, err := s.db.Exec(ctx,
		"INSERT INTO Canal_Estado_Atual (id_canal, tipo, state_key, id_evento) VALUES ($1, $2, $3, $4) ON CONFLICT (id_canal, tipo, state_key) DO UPDATE SET id_evento = $4",
		canalID, stateType, stateKey, eventID)
	if err != nil {
		return fmt.Errorf("failed to upsert current state: %w", err)
	}

	return nil
}

func (s *PostgresStorage) GetAllPublic(ctx context.Context, offset, limit int) ([]domain.Canal, error) {
	// TODO: não está filtrando por canais publicos
	rows, err := s.db.Query(ctx,
		"SELECT id_canal, versao_canal, criador, created_at FROM Canal ORDER BY created_at DESC LIMIT $1 OFFSET $2",
		limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get public canals: %w", err)
	}
	defer rows.Close()

	var canals []domain.Canal
	for rows.Next() {
		var canal domain.Canal
		if err := rows.Scan(&canal.ID, &canal.Versao, &canal.Criador, &canal.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan canal: %w", err)
		}
		canals = append(canals, canal)
	}

	return canals, nil
}

func (s *PostgresStorage) UpdateForwardExtremities(ctx context.Context, canalID string, extremeties []string) error {
	_, err := s.db.Exec(ctx, "DELETE FROM Canal_Extremidades WHERE id_canal = $1", canalID)
	if err != nil {
		return fmt.Errorf("failed to delete old extremities: %w", err)
	}

	for _, eventID := range extremeties {
		_, err := s.db.Exec(ctx,
			"INSERT INTO Canal_Extremidades (id_canal, id_evento) VALUES ($1, $2)",
			canalID, eventID)
		if err != nil {
			return fmt.Errorf("failed to insert extremity: %w", err)
		}
	}

	return nil
}

func (s *PostgresStorage) GetForwardExtremities(ctx context.Context, canalID string) ([]string, error) {
	rows, err := s.db.Query(ctx,
		"SELECT id_evento FROM Canal_Extremidades WHERE id_canal = $1",
		canalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get extremities: %w", err)
	}
	defer rows.Close()

	var eventIDs []string
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			return nil, fmt.Errorf("failed to scan event id: %w", err)
		}
		eventIDs = append(eventIDs, eventID)
	}

	return eventIDs, nil
}

func (s *PostgresStorage) SaveAlias(ctx context.Context, roomID, fullAlias string) error {
	_, err := s.db.Exec(ctx,
		"INSERT INTO Canal_Alias (id_canal, alias, id_evento) VALUES ($1, $2, '') ON CONFLICT (id_canal, alias) DO NOTHING",
		roomID, fullAlias)
	if err != nil {
		return fmt.Errorf("failed to save alias: %w", err)
	}

	return nil
}
