package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
	"github.com/jackc/pgx/v5"
)

func (s *PostgresStorage) CreateUsuarioAndProfile(ctx context.Context, userProps domain.Usuario) (*domain.Usuario, error) {
	db := getTxOrPool(ctx, s.db)
	row := db.QueryRow(ctx,
		"INSERT INTO Usuario (id_usuario, localpart, senha_hash, created_at) VALUES ($1, $2, $3, $4) RETURNING id_usuario, localpart, senha_hash, created_at",
		userProps.ID, userProps.LocalPart, userProps.SenhaHash, userProps.DataCriacao)

	var user domain.Usuario
	err := row.Scan(&user.ID, &user.LocalPart, &user.SenhaHash, &user.DataCriacao)
	if err != nil {
		return nil, fmt.Errorf("failed to create usuario: %w", err)
	}

	_, err = db.Exec(ctx,
		"INSERT INTO Profile (fk_usuario_id, nome) VALUES ($1, $2)",
		user.ID, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create profile: %w", err)
	}

	return &user, nil
}

func (s *PostgresStorage) GetUsuarioByID(ctx context.Context, userID string) (*domain.Usuario, error) {
	db := getTxOrPool(ctx, s.db)
	row := db.QueryRow(ctx,
		"SELECT id_usuario, localpart, senha_hash, created_at FROM Usuario WHERE id_usuario = $1",
		userID)

	var user domain.Usuario
	err := row.Scan(&user.ID, &user.LocalPart, &user.SenhaHash, &user.DataCriacao)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get usuario: %w", err)
	}

	return &user, nil
}

func (s *PostgresStorage) GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error) {
	db := getTxOrPool(ctx, s.db)
	row := db.QueryRow(ctx,
		"SELECT fk_usuario_id, nome, foto_url FROM Profile WHERE fk_usuario_id = $1",
		userID)

	var profile domain.Profile
	err := row.Scan(&profile.IDUsuario, &profile.DisplayName, &profile.AvatarURL)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get profile: %w", err)
	}

	return &profile, nil
}

func (s *PostgresStorage) UpdateProfile(ctx context.Context, profile domain.Profile) error {
	db := getTxOrPool(ctx, s.db)
	_, err := db.Exec(ctx,
		"UPDATE Profile SET nome = $1, foto_url = $2 WHERE fk_usuario_id = $3",
		profile.DisplayName, profile.AvatarURL, profile.IDUsuario)
	if err != nil {
		return fmt.Errorf("failed to update profile: %w", err)
	}

	return nil
}

func (s *PostgresStorage) SearchProfiles(ctx context.Context, filter usecase.SearchFilter) ([]domain.Profile, error) {
	query := "SELECT fk_usuario_id, nome, foto_url FROM Profile WHERE nome ILIKE $1 LIMIT $2 OFFSET $3"
	termPattern := fmt.Sprintf("%%%s%%", filter.Term)
	offset := 0
	if filter.NextToken != "" {
		fmt.Sscanf(filter.NextToken, "%d", &offset)
	}

	rows, err := s.db.Query(ctx, query, termPattern, filter.Limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to search profiles: %w", err)
	}
	defer rows.Close()

	var profiles []domain.Profile
	for rows.Next() {
		var profile domain.Profile
		if err := rows.Scan(&profile.IDUsuario, &profile.DisplayName, &profile.AvatarURL); err != nil {
			return nil, fmt.Errorf("failed to scan profile: %w", err)
		}
		profiles = append(profiles, profile)
	}

	return profiles, nil
}

func (s *PostgresStorage) AddDirectMessage(ctx context.Context, senderID, receiverID string, roomID string) error {
	db := getTxOrPool(ctx, s.db)
	_, err := db.Exec(ctx,
		"INSERT INTO AccountData (fk_id_usuario, id_canal, tipo, content) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
		senderID, roomID, "m.direct", "{\"friend\": \"true\"}")
	if err != nil {
		return fmt.Errorf("failed to add direct message: %w", err)
	}

	return nil
}

// SaveAccountData upserts an account_data row
func (s *PostgresStorage) SaveAccountData(ctx context.Context, account domain.AccountData) error {
	db := getTxOrPool(ctx, s.db)
	_, err := db.Exec(ctx,
		`INSERT INTO AccountData (fk_id_usuario, id_canal, tipo, content) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (fk_id_usuario, id_canal, tipo) DO UPDATE SET content = EXCLUDED.content`,
		account.IDUsuario, account.IDCanal, account.Tipo, account.Content)
	if err != nil {
		return fmt.Errorf("failed to save account data: %w", err)
	}
	return nil
}

// GetAccountData retrieves a single account_data row
func (s *PostgresStorage) GetAccountData(ctx context.Context, userID, roomID, tipo string) (*domain.AccountData, error) {
	db := getTxOrPool(ctx, s.db)
	row := db.QueryRow(ctx,
		"SELECT fk_id_usuario, id_canal, tipo, content FROM AccountData WHERE fk_id_usuario = $1 AND id_canal = $2 AND tipo = $3",
		userID, roomID, tipo)

	var acct domain.AccountData
	var contentBytes []byte
	if err := row.Scan(&acct.IDUsuario, &acct.IDCanal, &acct.Tipo, &contentBytes); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get account data: %w", err)
	}
	acct.Content = json.RawMessage(contentBytes)
	return &acct, nil
}

// GetGlobalAccountData retrieves all account_data rows for a user
func (s *PostgresStorage) GetGlobalAccountData(ctx context.Context, userID string) ([]domain.AccountData, error) {
	db := getTxOrPool(ctx, s.db)
	rows, err := db.Query(ctx,
		"SELECT fk_id_usuario, id_canal, tipo, content FROM AccountData WHERE fk_id_usuario = $1",
		userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get global account data: %w", err)
	}
	defer rows.Close()

	var accounts []domain.AccountData
	for rows.Next() {
		var acct domain.AccountData
		var contentBytes []byte
		if err := rows.Scan(&acct.IDUsuario, &acct.IDCanal, &acct.Tipo, &contentBytes); err != nil {
			return nil, fmt.Errorf("failed to scan global account data: %w", err)
		}
		acct.Content = json.RawMessage(contentBytes)
		accounts = append(accounts, acct)
	}
	return accounts, nil
}

// GetAccountDataOfCanal retrieves all account_data rows for a user in one room.
func (s *PostgresStorage) GetAccountDataOfCanal(ctx context.Context, userID string, canalID string) ([]domain.AccountData, error) {
	db := getTxOrPool(ctx, s.db)
	rows, err := db.Query(ctx,
		"SELECT fk_id_usuario, id_canal, tipo, content FROM AccountData WHERE fk_id_usuario = $1 AND id_canal = $2",
		userID, canalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get account data of canal: %w", err)
	}
	defer rows.Close()

	var accounts []domain.AccountData
	for rows.Next() {
		var acct domain.AccountData
		var contentBytes []byte
		if err := rows.Scan(&acct.IDUsuario, &acct.IDCanal, &acct.Tipo, &contentBytes); err != nil {
			return nil, fmt.Errorf("failed to scan account data of canal: %w", err)
		}
		acct.Content = json.RawMessage(contentBytes)
		accounts = append(accounts, acct)
	}

	return accounts, nil
}

// GetInviteEventsSince retrieves invite membership events for a user after a sync token.
func (s *PostgresStorage) GetInviteEventsSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error) {
	db := getTxOrPool(ctx, s.db)
	rows, err := db.Query(ctx, `
		SELECT e.id_evento, e.tipo, e.id_canal, e.sender, e.origin_server_ts, e.content, e.stream_ordering, e.state_key
		FROM Canal_Membership cm
		INNER JOIN Evento e ON e.id_evento = cm.id_evento
		WHERE cm.id_usuario = $1
		  AND cm.membership_type = 'invite'
		  AND e.stream_ordering > $2
		ORDER BY e.stream_ordering ASC
	`, userID, since.TimelinePosition)
	if err != nil {
		return nil, fmt.Errorf("failed to get invite events since: %w", err)
	}
	defer rows.Close()

	var eventos []domain.Evento
	for rows.Next() {
		var event domain.Evento
		var stateKey sql.NullString
		if err := rows.Scan(&event.ID, &event.Tipo, &event.CanalID, &event.Sender, &event.OrigemServidorTS, &event.Content, &event.StreamOrdering, &stateKey); err != nil {
			return nil, fmt.Errorf("failed to scan invite event: %w", err)
		}
		if stateKey.Valid {
			event.StateKey = &stateKey.String
		}
		eventos = append(eventos, event)
	}

	return eventos, nil
}
