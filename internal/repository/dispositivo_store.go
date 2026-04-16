package repository

import (
	"context"
	"database/sql"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type DeviceStore interface {
	GetAll(ctx context.Context, filter util.Filter) ([]model.Dispositivo, error)
	GetByID(ctx context.Context, id string) (*model.Dispositivo, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*model.Dispositivo, error)
	Create(ctx context.Context, props *model.Dispositivo) error
	Update(ctx context.Context, props *model.Dispositivo) error
	CreateOrUpdate(ctx context.Context, props *model.Dispositivo) error
	Delete(ctx context.Context, id string) (*model.Dispositivo, error)
}

type dispositivoStore struct {
	db *sql.DB
}

func NewDispositivoStore(db *sql.DB) DeviceStore {
	return &dispositivoStore{db}
}

func (s *dispositivoStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Dispositivo, error) {
	query := "SELECT d.id_dispositivo, d.fk_id_usuario, d.nome_dispositivo, d.refresh_token, d.refresh_token_expires_at, d.ultimo_ip_visto, d.ultimo_timestamp_visto FROM dispositivo d"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "d")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dispositivo := make([]model.Dispositivo, 0)
	for rows.Next() {
		var d model.Dispositivo
		err = rows.Scan(&d.ID, &d.UsuarioID, &d.Nome, &d.RefreshToken, &d.RefreshTokenExpiresAt, &d.UltimoIPVisto, &d.UltimoTimestampVisto)
		if err != nil {
			return nil, err
		}
		dispositivo = append(dispositivo, d)
	}
	return dispositivo, nil
}

func (s *dispositivoStore) GetByID(ctx context.Context, id string) (*model.Dispositivo, error) {
	query := "SELECT id_dispositivo, fk_id_usuario, nome_dispositivo, refresh_token, refresh_token_expires_at, ultimo_ip_visto, ultimo_timestamp_visto FROM dispositivo WHERE id_dispositivo = $1;"
	row := s.db.QueryRowContext(ctx, query, id)

	var d model.Dispositivo
	err := row.Scan(&d.ID, &d.UsuarioID, &d.Nome, &d.RefreshToken, &d.RefreshTokenExpiresAt, &d.UltimoIPVisto, &d.UltimoTimestampVisto)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

func (s *dispositivoStore) GetByRefreshToken(ctx context.Context, refreshToken string) (*model.Dispositivo, error) {
	query := "SELECT id_dispositivo, fk_id_usuario, nome_dispositivo, refresh_token, refresh_token_expires_at, ultimo_ip_visto, ultimo_timestamp_visto FROM dispositivo WHERE refresh_token = $1;"
	row := s.db.QueryRowContext(ctx, query, refreshToken)

	var d model.Dispositivo
	err := row.Scan(&d.ID, &d.UsuarioID, &d.Nome, &d.RefreshToken, &d.RefreshTokenExpiresAt, &d.UltimoIPVisto, &d.UltimoTimestampVisto)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

func (s *dispositivoStore) Create(ctx context.Context, props *model.Dispositivo) error {
	var err error
	if props.ID == "" {
		query := "INSERT INTO dispositivo (fk_id_usuario, nome_dispositivo, refresh_token, refresh_token_expires_at, ultimo_ip_visto, ultimo_timestamp_visto) VALUES ($1, $2, $3, $4, $5, $6);"
		_, err = s.db.ExecContext(ctx, query, props.UsuarioID, props.Nome, props.RefreshToken, props.RefreshTokenExpiresAt, props.UltimoIPVisto, props.UltimoTimestampVisto)
	} else {
		query := "INSERT INTO dispositivo (id_dispositivo, fk_id_usuario, nome_dispositivo, refresh_token, refresh_token_expires_at, ultimo_ip_visto, ultimo_timestamp_visto) VALUES ($1, $2, $3, $4, $5, $6, $7);"
		_, err = s.db.ExecContext(ctx, query, props.ID, props.UsuarioID, props.Nome, props.RefreshToken, props.RefreshTokenExpiresAt, props.UltimoIPVisto, props.UltimoTimestampVisto)
	}
	return err
}

func (s *dispositivoStore) Update(ctx context.Context, props *model.Dispositivo) error {
	query := "UPDATE dispositivo SET nome_dispositivo = $1, fk_id_usuario = $2, refresh_token = $3, refresh_token_expires_at = $4, ultimo_ip_visto = $5, ultimo_timestamp_visto = $6 WHERE id_dispositivo = $7"
	res, err := s.db.ExecContext(ctx, query, props.Nome, props.UsuarioID, props.RefreshToken, props.RefreshTokenExpiresAt, props.UltimoIPVisto, props.UltimoTimestampVisto, props.ID)
	if err != nil {
		return err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return types.ErrNotFound
	}
	return nil
}

func (s *dispositivoStore) CreateOrUpdate(ctx context.Context, props *model.Dispositivo) error {
	query := "INSERT INTO dispositivo (id_dispositivo, fk_id_usuario, nome_dispositivo, refresh_token, refresh_token_expires_at, ultimo_ip_visto, ultimo_timestamp_visto) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id_dispositivo) DO UPDATE SET fk_id_usuario = $2, nome_dispositivo = $3, refresh_token = $4, refresh_token_expires_at = $5, ultimo_ip_visto = $6, ultimo_timestamp_visto = $7"
	_, err := s.db.ExecContext(ctx, query, props.ID, props.UsuarioID, props.Nome, props.RefreshToken, props.RefreshTokenExpiresAt, props.UltimoIPVisto, props.UltimoTimestampVisto)
	return err
}

func (s *dispositivoStore) Delete(ctx context.Context, id_dispositivo string) (*model.Dispositivo, error) {
	dispositivo, err := s.GetByID(ctx, id_dispositivo)
	if err != nil {
		return nil, err
	}

	query := "DELETE FROM dispositivo WHERE id_dispositivo = $1"
	res, err := s.db.ExecContext(ctx, query, dispositivo.ID)
	if err != nil {
		return nil, err
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		return nil, types.ErrNotFound
	}

	return dispositivo, nil
}
