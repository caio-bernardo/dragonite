package postgres

import (
	"context"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/jackc/pgx/v5"
)

// SaveMidia persiste os metadados de um arquivo de mídia no banco de dados.
// O arquivo em si é armazenado no MinIO, aqui só ficam os dados descritivos.
func (s *PostgresStorage) SaveMidia(ctx context.Context, midia *domain.Midia) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO Midia (id_midia, origin, content_type, size_bytes, upload_name, id_usuario, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, midia.IDMidia, midia.Origin, midia.ContentType, midia.SizeBytes, midia.UploadName, midia.IDUsuario, midia.CreatedAt)
	if err != nil {
		return fmt.Errorf("failure to save media metadata '%s': %w", midia.IDMidia, err)
	}

	return nil
}

// GetMidiaByID recupera os metadados de uma mídia pelo par (origin, id_midia),
// que corresponde à chave primária composta da tabela Midia.
func (s *PostgresStorage) GetMidiaByID(ctx context.Context, origin, idMidia string) (*domain.Midia, error) {
	row := s.db.QueryRow(ctx, `
		SELECT id_midia, origin, content_type, size_bytes, upload_name, id_usuario, created_at
		FROM Midia
		WHERE origin = $1 AND id_midia = $2
	`, origin, idMidia)

	var midia domain.Midia
	err := row.Scan(
		&midia.IDMidia,
		&midia.Origin,
		&midia.ContentType,
		&midia.SizeBytes,
		&midia.UploadName,
		&midia.IDUsuario,
		&midia.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch media '%s/%s': %w", origin, idMidia, err)
	}

	return &midia, nil
}