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
		-- CORREÇÃO: Adicionadas as colunas prev_eventos, auth_eventos e depth no SELECT final
		SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, stream_ordering, state_key, prev_eventos, auth_eventos, depth
		FROM dag_backfill
		ORDER BY depth DESC, distance ASC
		LIMIT $3;
	`
	rows, err := s.db.Query(ctx, query, roomID, pq.Array(events), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get events for backfill: %w", err)
	}
	defer rows.Close()

	var eventos []domain.Evento
	for rows.Next() {
		var event domain.Evento
		var stateKey sql.NullString
		// Agora o número de argumentos no Scan (11) bate certo com o SELECT (11)
		err := rows.Scan(
			&event.ID, &event.Tipo, &event.CanalID, &event.Sender,
			&event.OrigemServidorTS, &event.Content, &event.StreamOrdering,
			&stateKey, pq.Array(&event.PrevEventos), pq.Array(&event.AuthEventos), &event.Depth,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan backfill event: %w", err)
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

func (s *PostgresStorage) GetCurrentStateEvents(ctx context.Context, roomID string) ([]domain.Evento, error) {
	query := `
        SELECT e.id_evento, e.tipo, e.id_canal, e.sender, e.origin_server_ts,
               e.content, e.state_key, e.prev_eventos, e.auth_eventos, e.depth
        FROM Canal_Estado_Atual cea
        JOIN Evento e ON e.id_evento = cea.id_evento
        WHERE cea.id_canal = $1`

	rows, err := s.db.Query(ctx, query, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current state events: %w", err)
	}
	defer rows.Close()

	var eventos []domain.Evento
	for rows.Next() {
		var event domain.Evento
		var stateKey sql.NullString
		err := rows.Scan(
			&event.ID, &event.Tipo, &event.CanalID, &event.Sender,
			&event.OrigemServidorTS, &event.Content, &stateKey,
			pq.Array(&event.PrevEventos), pq.Array(&event.AuthEventos), &event.Depth,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan state event: %w", err)
		}
		if stateKey.Valid {
			event.StateKey = &stateKey.String
		}
		eventos = append(eventos, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return eventos, nil
}

func (s *PostgresStorage) GetRoomMessagesHistory(ctx context.Context, roomID string, fromToken int64, dir string, limit int) ([]domain.Evento, error) {
	var query string
	var args []interface{} // Faremos um slice com os argumentos da query

	// A paginação depende da direção ("b" ou "f") e se um token foi fornecido
	if dir == "b" {
		if fromToken == 0 {
			// Se não há token e vamos para trás, trazemos os mais recentes
			query = `SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, state_key, stream_ordering
					 FROM Evento WHERE id_canal = $1 ORDER BY stream_ordering DESC LIMIT $2`
			args = []interface{}{roomID, limit}
		} else {
			// Se há token, trazemos os mais antigos do que o token
			query = `SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, state_key, stream_ordering
					 FROM Evento WHERE id_canal = $1 AND stream_ordering < $2 ORDER BY stream_ordering DESC LIMIT $3`
			args = []interface{}{roomID, fromToken, limit}
		}
	} else {
		// Direção "f" (forward): trazemos os eventos mais recentes do que o token
		query = `SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, state_key, stream_ordering
				 FROM Evento WHERE id_canal = $1 AND stream_ordering > $2 ORDER BY stream_ordering ASC LIMIT $3`
		args = []interface{}{roomID, fromToken, limit}
	}

	// Usamos ':=' para o Go inferir automaticamente que 'rows' é do tipo pgx.Rows
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute history query: %w", err)
	}
	defer rows.Close()

	var eventos []domain.Evento
	for rows.Next() {
		var event domain.Evento
		var stateKey sql.NullString
		err := rows.Scan(
			&event.ID, &event.Tipo, &event.CanalID, &event.Sender,
			&event.OrigemServidorTS, &event.Content, &stateKey, &event.StreamOrdering,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event for history: %w", err)
		}
		if stateKey.Valid {
			event.StateKey = &stateKey.String
		}
		eventos = append(eventos, event)
	}

	return eventos, nil
}

func (s *PostgresStorage) GetStateAndAuthChainIDs(ctx context.Context, roomID string, eventID string) ([]string, []string, error) {
	// Ir buscar os PDU IDs (Os eventos de estado propriamente ditos)

	stateQuery := `
		SELECT e.id_evento
		FROM Canal_Estado_Atual cea
		JOIN Evento e ON e.id_evento = cea.id_evento
		WHERE cea.id_canal = $1
	`
	rows, err := s.db.Query(ctx, stateQuery, roomID)
	if err != nil {
		return nil, nil, fmt.Errorf("query state failed: %w", err)
	}
	defer rows.Close()

	var pduIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			pduIDs = append(pduIDs, id)
		}
	}
	rows.Close() // Fechar cedo para liberar a conexão

	if len(pduIDs) == 0 {
		return []string{}, []string{}, nil
	}

	authChainQuery := `
		WITH RECURSIVE auth_tree AS (
			-- Caso Base: Os auth_events diretamente referenciados pelos PDU_IDs encontrados
			SELECT unnest(auth_eventos) as auth_id
			FROM Evento
			WHERE id_evento = ANY($1)

			UNION

			-- Passo Recursivo: Buscar os auth_events dos eventos encontrados no passo anterior
			SELECT unnest(e.auth_eventos)
			FROM Evento e
			INNER JOIN auth_tree at ON e.id_evento = at.auth_id
			WHERE e.auth_eventos IS NOT NULL
		)
		SELECT DISTINCT auth_id FROM auth_tree WHERE auth_id IS NOT NULL;
	`

	authRows, err := s.db.Query(ctx, authChainQuery, pq.Array(pduIDs))
	if err != nil {
		return nil, nil, fmt.Errorf("query auth chain failed: %w", err)
	}
	defer authRows.Close()

	var authChainIDs []string
	for authRows.Next() {
		var authID string
		if err := authRows.Scan(&authID); err == nil {
			authChainIDs = append(authChainIDs, authID)
		}
	}

	return pduIDs, authChainIDs, nil
}

func (s *PostgresStorage) GetMissingEvents(ctx context.Context, roomID string, earliestEvents, latestEvents []string, limit int, minDepth int64) ([]domain.Evento, error) {
	// Prevenção contra nil slices que o driver do Postgres não gosta no pq.Array
	if earliestEvents == nil { earliestEvents = []string{} }
	if latestEvents == nil { latestEvents = []string{} }

	query := `
		WITH RECURSIVE missing_tree AS (
			-- Caso Base: Os latest_events conhecidos pelo servidor remoto
			SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, stream_ordering, state_key, prev_eventos, auth_eventos, depth, 1 AS distance
			FROM Evento
			WHERE id_canal = $1 AND id_evento = ANY($2)

			UNION

			-- Passo Recursivo: Descer na árvore de prev_eventos
			SELECT e.id_evento, e.tipo, e.id_canal, e.sender, e.origin_server_ts, e.content, e.stream_ordering, e.state_key, e.prev_eventos, e.auth_eventos, e.depth, mt.distance + 1
			FROM Evento e
			JOIN missing_tree mt ON e.id_evento = ANY(mt.prev_eventos)
			WHERE
				-- Condições de paragem exigidas pelo protocolo Matrix:
				NOT (e.id_evento = ANY($3)) -- Pára se encontrar um earliest_event
				AND e.depth >= $4           -- Pára se for mais profundo do que min_depth
				AND mt.distance <= $5       -- Limite de segurança da recursão = limit param
		)
		SELECT id_evento, tipo, id_canal, sender, origin_server_ts, content, stream_ordering, state_key, prev_eventos, auth_eventos, depth
		FROM missing_tree
		-- A especificação determina que a resposta NÃO pode conter os latest_events nem os earliest_events
		WHERE NOT (id_evento = ANY($2)) AND NOT (id_evento = ANY($3))
		-- A resposta deve vir ordenada por profundidade topológica (do mais antigo para o mais recente)
		ORDER BY depth ASC
		LIMIT $5;
	`

	rows, err := s.db.Query(ctx, query, roomID, pq.Array(latestEvents), pq.Array(earliestEvents), minDepth, limit)
	if err != nil {
		return nil, fmt.Errorf("query missing events failed: %w", err)
	}
	defer rows.Close()

	var eventos []domain.Evento
	for rows.Next() {
		var event domain.Evento
		var stateKey sql.NullString

		err := rows.Scan(
			&event.ID, &event.Tipo, &event.CanalID, &event.Sender,
			&event.OrigemServidorTS, &event.Content, &event.StreamOrdering,
			&stateKey, pq.Array(&event.PrevEventos), pq.Array(&event.AuthEventos), &event.Depth,
		)
		if err != nil {
			return nil, fmt.Errorf("scan missing events failed: %w", err)
		}
		if stateKey.Valid {
			event.StateKey = &stateKey.String
		}
		eventos = append(eventos, event)
	}

	return eventos, nil
}

func (s *PostgresStorage) SaveReceipt(ctx context.Context, userID, roomID, receiptType, eventID string, ts int64) error {

	query := `
		INSERT INTO read_receipts (room_id, user_id, event_id, ts)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (room_id, user_id)
		DO UPDATE SET
			event_id = EXCLUDED.event_id,
			ts = EXCLUDED.ts;
	`

	_, err := s.db.Exec(ctx, query, roomID, userID, eventID, ts)
	if err != nil {
		return fmt.Errorf("failed to execute upsert read receipt query: %w", err)
	}

	return nil
}
