package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/jackc/pgx/v5"
)

func (s *PostgresStorage) SearchDirectory(ctx context.Context, term string, limit, offset int) ([]domain.PublicRoomEntry, int, error) {
	termPattern := fmt.Sprintf("%%%s%%", term)

	// 1. Get total count of matching rooms first
	countRow := s.db.QueryRow(ctx,
		`SELECT COUNT(DISTINCT c.id_canal)
		 FROM Canal c
		 LEFT JOIN Canal_Estado_Atual cec ON c.id_canal = cec.id_canal
		 LEFT JOIN Evento e ON cec.id_evento = e.id_evento
		 WHERE (cec.tipo = 'm.room.name' OR cec.tipo = 'm.room.topic')
		   AND e.content::text ILIKE $1`,
		termPattern)

	var total int
	if err := countRow.Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to get total count: %w", err)
	}

	if total == 0 {
		return []domain.PublicRoomEntry{}, 0, nil
	}

	// 2. Fetch rooms with full state enrichment using a CTE
	query := `
			WITH matched_rooms AS (
				SELECT DISTINCT c.id_canal
				FROM Canal c
				LEFT JOIN Canal_Estado_Atual cec ON c.id_canal = cec.id_canal
				LEFT JOIN Evento e ON cec.id_evento = e.id_evento
				WHERE (cec.tipo = 'm.room.name' OR cec.tipo = 'm.room.topic')
				  AND e.content::text ILIKE $1
				LIMIT $2 OFFSET $3
			)
			SELECT
				mr.id_canal,
				name_ev.content->>'name' AS name,
				topic_ev.content->>'topic' AS topic,
				avatar_ev.content->>'url' AS avatar_url,
				alias_ev.content->>'alias' AS canonical_alias,
				rules_ev.content->>'join_rule' AS join_rule,
				COALESCE(
					(SELECT COUNT(*)
					 FROM Canal_Membership cm
					 WHERE cm.id_canal = mr.id_canal
					   AND cm.membership_type = 'join'),
					0
				) AS num_joined_members,
				COALESCE(hist_ev.content->>'history_visibility' = 'world_readable', false) AS world_readable,
				COALESCE(guest_ev.content->>'guest_access' = 'can_join', false) AS guest_can_join
			FROM matched_rooms mr
			LEFT JOIN Canal_Estado_Atual cs_name ON mr.id_canal = cs_name.id_canal AND cs_name.tipo = 'm.room.name'
			LEFT JOIN Evento name_ev ON cs_name.id_evento = name_ev.id_evento
			LEFT JOIN Canal_Estado_Atual cs_topic ON mr.id_canal = cs_topic.id_canal AND cs_topic.tipo = 'm.room.topic'
			LEFT JOIN Evento topic_ev ON cs_topic.id_evento = topic_ev.id_evento
			LEFT JOIN Canal_Estado_Atual cs_avatar ON mr.id_canal = cs_avatar.id_canal AND cs_avatar.tipo = 'm.room.avatar'
			LEFT JOIN Evento avatar_ev ON cs_avatar.id_evento = avatar_ev.id_evento
			LEFT JOIN Canal_Estado_Atual cs_alias ON mr.id_canal = cs_alias.id_canal AND cs_alias.tipo = 'm.room.canonical_alias'
			LEFT JOIN Evento alias_ev ON cs_alias.id_evento = alias_ev.id_evento
			LEFT JOIN Canal_Estado_Atual cs_rules ON mr.id_canal = cs_rules.id_canal AND cs_rules.tipo = 'm.room.join_rules'
			LEFT JOIN Evento rules_ev ON cs_rules.id_evento = rules_ev.id_evento
			LEFT JOIN Canal_Estado_Atual cs_hist ON mr.id_canal = cs_hist.id_canal AND cs_hist.tipo = 'm.room.history_visibility'
			LEFT JOIN Evento hist_ev ON cs_hist.id_evento = hist_ev.id_evento
			LEFT JOIN Canal_Estado_Atual cs_guest ON mr.id_canal = cs_guest.id_canal AND cs_guest.tipo = 'm.room.guest_access'
			LEFT JOIN Evento guest_ev ON cs_guest.id_evento = guest_ev.id_evento;`

	rows, err := s.db.Query(ctx, query, termPattern, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search directory: %w", err)
	}
	defer rows.Close()

	var entries []domain.PublicRoomEntry
	for rows.Next() {
		var (
			roomID           string
			name             *string
			topic            *string
			avatarURL        *string
			canonicalAlias   *string
			joinRule         *string
			numJoinedMembers int
			worldReadable    bool
			guestCanJoin     bool
		)

		// pgx automatically handles scanning SQL NULL into Go *string as nil
		if err := rows.Scan(
			&roomID,
			&name,
			&topic,
			&avatarURL,
			&canonicalAlias,
			&joinRule,
			&numJoinedMembers,
			&worldReadable,
			&guestCanJoin,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan room entry: %w", err)
		}

		entry := domain.PublicRoomEntry{
			RoomID:           roomID,
			Name:             name,
			Topic:            topic,
			AvatarURL:        avatarURL,
			CanonicalAlias:   canonicalAlias,
			NumJoinedMembers: numJoinedMembers,
			WorldReadable:    worldReadable,
			GuestCanJoin:     guestCanJoin,
			JoinRule:         joinRule,
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows iteration error: %w", err)
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
