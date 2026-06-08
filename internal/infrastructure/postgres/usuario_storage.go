package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/usecase"
	"github.com/jackc/pgx/v5"
)

func (s *PostgresStorage) CreateUsuarioAndProfile(ctx context.Context, userProps domain.Usuario) (*domain.Usuario, error) {
	row := s.db.QueryRow(ctx,
		"INSERT INTO Usuario (id_usuario, localpart, senha_hash, created_at) VALUES ($1, $2, $3, $4) RETURNING id_usuario, localpart, senha_hash, created_at",
		userProps.ID, userProps.LocalPart, userProps.SenhaHash, userProps.DataCriacao)

	var user domain.Usuario
	err := row.Scan(&user.ID, &user.LocalPart, &user.SenhaHash, &user.DataCriacao)
	if err != nil {
		return nil, fmt.Errorf("failed to create usuario: %w", err)
	}

	_, err = s.db.Exec(ctx,
		"INSERT INTO Profile (fk_usuario_id, nome) VALUES ($1, $2)",
		user.ID, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create profile: %w", err)
	}

	return &user, nil
}

func (s *PostgresStorage) GetUsuarioByID(ctx context.Context, userID string) (*domain.Usuario, error) {
	row := s.db.QueryRow(ctx,
		"SELECT id_usuario, localpart, senha_hash, created_at FROM Usuario WHERE id_usuario = $1",
		userID)

	var user domain.Usuario
	err := row.Scan(&user.ID, &user.LocalPart, &user.SenhaHash, &user.DataCriacao)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get usuario: %w", err)
	}

	return &user, nil
}

func (s *PostgresStorage) GetProfileByID(ctx context.Context, userID string) (*domain.Profile, error) {
	row := s.db.QueryRow(ctx,
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
	_, err := s.db.Exec(ctx,
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
	_, err := s.db.Exec(ctx,
		"INSERT INTO AccountData (fk_id_usuario, id_canal, tipo, content) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
		senderID, roomID, "m.direct", "{\"friend\": \"true\"}")
	if err != nil {
		return fmt.Errorf("failed to add direct message: %w", err)
	}

	return nil
}
