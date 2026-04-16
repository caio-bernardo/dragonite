package repository

import (
	"context"
	"database/sql"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type ChannelStore interface {
	GetAll(ctx context.Context, filter util.Filter) ([]model.Canal, error)
	GetByID(ctx context.Context, id string) (*model.Canal, error)
	Create(ctx context.Context, props *model.Canal) error
	Update(ctx context.Context, props *model.Canal) error
	Delete(ctx context.Context, id_canal string) (*model.Canal, error)
}

type canalStore struct {
	db *sql.DB
}

func NewChannelStore(db *sql.DB) ChannelStore {
	return &canalStore{db}
}

func (s *canalStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Canal, error) {
	query := "SELECT c.id_canal, c.nome_canal, c.descricao_canal, c.foto_canal, c.is_public_canal, c.versao_canal, c.fk_id_criador, c.data_criacao_canal FROM canal c"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "c")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	canal := make([]model.Canal, 0)
	for rows.Next() {
		var c model.Canal
		err = rows.Scan(&c.ID, &c.Nome, &c.Descricao, &c.Foto, &c.IsPublic, &c.Versao, &c.CriadorID, &c.DataCriacao)
		if err != nil {
			return nil, err
		}
		canal = append(canal, c)
	}
	return canal, nil
}

func (s *canalStore) GetByID(ctx context.Context, id string) (*model.Canal, error) {
	query := "SELECT id_canal, nome_canal, descricao_canal, foto_canal, is_public_canal, versao_canal, fk_id_criador, data_criacao_canal FROM canal WHERE id_canal = $1;"
	row := s.db.QueryRowContext(ctx, query, id)

	var c model.Canal
	err := row.Scan(&c.ID, &c.Nome, &c.Descricao, &c.Foto, &c.IsPublic, &c.Versao, &c.CriadorID, &c.DataCriacao)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (s *canalStore) Create(ctx context.Context, props *model.Canal) error {
	query := "INSERT INTO canal (id_canal, nome_canal, descricao_canal, foto_canal, is_public_canal, versao_canal, fk_id_criador, data_criacao_canal) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);"
	_, err := s.db.ExecContext(ctx, query, props.ID, props.Nome, props.Descricao, props.Foto, props.IsPublic, props.Versao, props.CriadorID, props.DataCriacao)
	return err
}

func (s *canalStore) Update(ctx context.Context, props *model.Canal) error {
	query := "UPDATE canal SET nome_canal = $1, descricao_canal = $2, foto_canal = $3, is_public_canal = $4, versao_canal = $5, fk_id_criador = $6, data_criacao_canal = $7 WHERE id_canal = $8"
	res, err := s.db.ExecContext(ctx, query, props.Nome, props.Descricao, props.Foto, props.IsPublic, props.Versao, props.CriadorID, props.DataCriacao, props.ID)
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

func (s *canalStore) Delete(ctx context.Context, id_canal string) (*model.Canal, error) {
	canal, err := s.GetByID(ctx, id_canal)
	if err != nil {
		return nil, err
	}

	_, err = s.db.ExecContext(ctx, "DELETE FROM usuario_canal WHERE fk_id_canal = $1", canal.ID)
	if err != nil {
		return nil, err
	}

	_, err = s.db.ExecContext(ctx, "DELETE FROM estado_atual_canal WHERE fk_id_canal = $1", canal.ID)
	if err != nil {
		return nil, err
	}

	_, err = s.db.ExecContext(ctx, "DELETE FROM evento WHERE fk_id_canal = $1", canal.ID)
	if err != nil {
		return nil, err
	}

	query := "DELETE FROM canal WHERE id_canal = $1"
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

	return canal, nil
}
