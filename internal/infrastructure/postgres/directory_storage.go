package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/jackc/pgx/v5"
)

func (s *PostgresStorage) SearchDirectory(ctx context.Context, term string, limit, offset int) ([]domain.PublicRoomEntry, int, error) {
	// Search for rooms by name or topic
	termPattern := fmt.Sprintf("%%%s%%", term)

	rows, err := s.db.Query(ctx,
		"SELECT DISTINCT c.id_canal FROM Canal c LEFT JOIN Canal_Estado_Atual cec ON c.id_canal = cec.id_canal LEFT JOIN Evento e ON cec.id_evento = e.id_evento WHERE (cec.tipo = 'm.room.name' OR cec.tipo = 'm.room.topic') AND e.content::text ILIKE $1 LIMIT $2 OFFSET $3",
		termPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search directory: %w", err)
	}
	defer rows.Close()

	var entries []domain.PublicRoomEntry
	for rows.Next() {
		var roomID string
		if err := rows.Scan(&roomID); err != nil {
			return nil, 0, fmt.Errorf("failed to scan room id: %w", err)
		}

		entry := domain.PublicRoomEntry{
			RoomID: roomID,
		}
		entries = append(entries, entry)
	}

	// Get total count
	countRow := s.db.QueryRow(ctx,
		"SELECT COUNT(DISTINCT c.id_canal) FROM Canal c LEFT JOIN Canal_Estado_Atual cec ON c.id_canal = cec.id_canal LEFT JOIN Evento e ON cec.id_evento = e.id_evento WHERE (cec.tipo = 'm.room.name' OR cec.tipo = 'm.room.topic') AND e.content::text ILIKE $1",
		termPattern)

	var total int
	if err := countRow.Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to get total count: %w", err)
	}

	return entries, total, nil
}

func (s *PostgresStorage) GetRoomIDByAlias(ctx context.Context, alias string) (string, error) {
	row := s.db.QueryRow(ctx, "SELECT id_canal FROM Canal_Alias WHERE alias = $1", alias)

	var roomID string
	err := row.Scan(&roomID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", types.ErrNotFound
		}
		return "", fmt.Errorf("failed to get room by alias: %w", err)
	}

	return roomID, nil
}

func (s *PostgresStorage) DeleteAlias(ctx context.Context, alias string) error {
	db := getTxOrPool(ctx, s.db)
	tag, err := db.Exec(ctx, "DELETE FROM Canal_Alias WHERE alias = $1", alias)
	if err != nil {
		return fmt.Errorf("failed to delete alias: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return types.ErrNotFound
	}

	return nil
}
