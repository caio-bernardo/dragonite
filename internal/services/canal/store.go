package canal

import (
	"context"
	"database/sql"
	"dragonite/internal/model"
	"dragonite/internal/types"
	"dragonite/internal/util"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db}
}

func (s *Store) GetAll(ctx context.Context, filter util.Filter) ([]model.Canal, error) {
	query := "SELECT id_canal, nome_canal, descricao_canal, foto_canal FROM canal"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "io")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	canal := make([]model.Canal, 0)
	for rows.Next() {
		var c model.Canal
		err = rows.Scan(&c.ID, &c.Nome, &c.Descricao, &c.Foto)
		if err != nil {
			return nil, err
		}
		canal = append(canal, c)
	}
	return canal, nil
}

func (s *Store) GetByID(ctx context.Context, id int64) (*model.Canal, error) {
	query := "SELECT id_canal, nome_canal, descricao_canal, foto_canal FROM canal WHERE id_canal = $1;"
	row := s.db.QueryRowContext(ctx, query, id)

	var c model.Canal
	err := row.Scan(&c.ID, &c.Nome, &c.Descricao, &c.Foto)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (s *Store) Create(ctx context.Context, props *model.Canal) error {
	query := "INSERT INTO canal (id_canal, nome_canal, descricao_canal, foto_canal) VALUES ($1, $2, $3, $4);"
	_, err := s.db.ExecContext(ctx, query, props.ID, props.Nome, props.Descricao, props.Foto)
	return err
}

func (s *Store) Update(ctx context.Context, props *model.Canal) error {
	query := "UPDATE canal SET nome_canal = $1, descricao_canal = $2, foto_canal = $3 WHERE id_canal = $4"
	res, err := s.db.ExecContext(ctx, query, props.Nome, props.Descricao, props.Foto, props.ID)
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

func (s *Store) Delete(ctx context.Context, id_canal int64) (*model.Canal, error) {
	canal, err := s.GetByID(ctx, id_canal)
	if err != nil {
		return nil, err
	}

	query := "DELETE FROM contem_canal WHERE id_canal = $1"
	res, err := s.db.ExecContext(ctx, query, canal.ID)
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

	query = "DELETE FROM canal WHERE id_canal = $1"
	res, err = s.db.ExecContext(ctx, query, canal.ID)
	if err != nil {
		return nil, err
	}

	rowsAffected, err = res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rowsAffected == 0 {
		return nil, types.ErrNotFound
	}

	return canal, nil
}
