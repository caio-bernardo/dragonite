package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
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
