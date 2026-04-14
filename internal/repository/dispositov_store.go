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
	GetByID(ctx context.Context, id int64) (*model.Dispositivo, error)
	Create(ctx context.Context, props *model.Dispositivo) error
	Update(ctx context.Context, props *model.Dispositivo) error
	Delete(ctx context.Context, id int64) (*model.Dispositivo, error)
}

type dispositivoStore struct {
	db *sql.DB
}

func NewDispositivoStore(db *sql.DB) DeviceStore {
	return &dispositivoStore{db}
}

func (s *dispositivoStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Dispositivo, error) {
	query := "SELECT id_dispositivo, nome_dispositivo, ultimo_ip_visto, ultimo_timestamp_visto FROM dispositivo"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "io")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dispositivo := make([]model.Dispositivo, 0)
	for rows.Next() {
		var d model.Dispositivo
		err = rows.Scan(&d.ID, &d.Nome, &d.UltimoIPVisto, &d.UltimoTimestampVisto)
		if err != nil {
			return nil, err
		}
		dispositivo = append(dispositivo, d)
	}
	return dispositivo, nil
}

func (s *dispositivoStore) GetByID(ctx context.Context, id int64) (*model.Dispositivo, error) {
	query := "SELECT id_dispositivo, nome_dispositivo, ultimo_ip_visto, ultimo_timestamp_visto FROM dispositivo WHERE id_dispositivo = $1;"
	row := s.db.QueryRowContext(ctx, query, id)

	var d model.Dispositivo
	err := row.Scan(&d.ID, &d.Nome, &d.UltimoIPVisto, &d.UltimoTimestampVisto)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

func (s *dispositivoStore) Create(ctx context.Context, props *model.Dispositivo) error {
	query := "INSERT INTO dispositivo (id_dispositivo, nome_dispositivo, ultimo_ip_visto, ultimo_timestamp_visto) VALUES ($1, $2, $3, $4);"
	_, err := s.db.ExecContext(ctx, query, props.ID, props.Nome, props.UltimoIPVisto, props.UltimoTimestampVisto)
	return err
}

func (s *dispositivoStore) Update(ctx context.Context, props *model.Dispositivo) error {
	query := "UPDATE dispositivo SET nome_dispositivo = $1, ultimo_ip_visto = $2, ultimo_timestamp_visto = $3 WHERE id_dispositivo = $4"
	res, err := s.db.ExecContext(ctx, query, props.Nome, props.UltimoIPVisto, props.UltimoTimestampVisto, props.ID)
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

func (s *dispositivoStore) Delete(ctx context.Context, id_dispositivo int64) (*model.Dispositivo, error) {
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
