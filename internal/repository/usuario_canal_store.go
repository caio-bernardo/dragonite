package repository

import (
	"context"
	"database/sql"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type UsuarioCanalStore interface {
	GetAll(ctx context.Context, filter util.Filter) ([]model.UsuarioCanal, error)
	GetByID(ctx context.Context, id int64) (*model.UsuarioCanal, error)
	GetByComposedID(ctx context.Context, id_usuario int64, id_canal int64) (*model.UsuarioCanal, error)
	GetAllByUsuarioID(ctx context.Context, id_usuario int64) ([]model.UsuarioCanal, error)
	GetAllByCanalID(ctx context.Context, id_canal int64) ([]model.UsuarioCanal, error)
	Create(ctx context.Context, props *model.UsuarioCanal) error
	Update(ctx context.Context, props *model.UsuarioCanal) error
	Delete(ctx context.Context, id_usuario int64, id_canal int64) (*model.UsuarioCanal, error)
}

type usuarioCanalStore struct {
	db *sql.DB
}

func NewUsuarioCanalStore(db *sql.DB) UsuarioCanalStore {
	return &usuarioCanalStore{db}
}

func (s *usuarioCanalStore) GetAll(ctx context.Context, filter util.Filter) ([]model.UsuarioCanal, error) {
	query := "SELECT id_usuario, id_canal, data_hora FROM usuario_canal"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "io")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	usuarios := make([]model.UsuarioCanal, 0)
	for rows.Next() {
		var d model.UsuarioCanal
		err = rows.Scan(&d.ID, &d.UsuarioID, &d.CanalID, &d.DataHora)
		if err != nil {
			return nil, err
		}
		usuarios = append(usuarios, d)
	}
	return usuarios, nil
}

func (s *usuarioCanalStore) GetByID(ctx context.Context, id int64) (*model.UsuarioCanal, error) {
	query := "SELECT id_usuario, id_canal, data_hora FROM usuario_canal WHERE id_usuario = $1 ;"
	row := s.db.QueryRowContext(ctx, query, id)

	var d model.UsuarioCanal
	err := row.Scan(&d.ID, &d.UsuarioID, &d.CanalID, &d.DataHora)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

// GetByComposedID busca uma entrada específica de ItemOferta pela sua chave primária composta.
func (s *usuarioCanalStore) GetByComposedID(ctx context.Context, id_usuario int64, id_canal int64) (*model.UsuarioCanal, error) {
	query := "SELECT id_usuario, id_canal, data_hora FROM usuario_canal WHERE id_usuario = $1 AND id_canal = $2"
	row := s.db.QueryRowContext(ctx, query, id_usuario, id_canal)

	var io model.UsuarioCanal
	err := row.Scan(&io.ID, &io.UsuarioID, &io.CanalID, &io.DataHora)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &io, nil
}

// GetAllByUsuarioID busca todas as entradas de UsuarioCanal para um determinado usuário.
func (s *usuarioCanalStore) GetAllByUsuarioID(ctx context.Context, id_usuario int64) ([]model.UsuarioCanal, error) {
	query := "SELECT id_usuario, id_canal, data_hora FROM usuario_canal WHERE id_usuario = $1"
	rows, err := s.db.QueryContext(ctx, query, id_usuario)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usuariosCanal []model.UsuarioCanal
	for rows.Next() {
		var uc model.UsuarioCanal
		err = rows.Scan(&uc.UsuarioID, &uc.CanalID, &uc.DataHora)
		if err != nil {
			return nil, err
		}
		usuariosCanal = append(usuariosCanal, uc)
	}
	return usuariosCanal, nil
}

// GetAllByCanalID busca todas as entradas de UsuarioCanal para um determinado canal.
func (s *usuarioCanalStore) GetAllByCanalID(ctx context.Context, id_canal int64) ([]model.UsuarioCanal, error) {
	query := "SELECT id_usuario, id_canal, data_hora FROM usuario_canal WHERE id_canal = $1"
	rows, err := s.db.QueryContext(ctx, query, id_canal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usuariosCanal []model.UsuarioCanal
	for rows.Next() {
		var uc model.UsuarioCanal
		err = rows.Scan(&uc.UsuarioID, &uc.CanalID, &uc.DataHora)
		if err != nil {
			return nil, err
		}
		usuariosCanal = append(usuariosCanal, uc)
	}
	return usuariosCanal, nil
}

func (s *usuarioCanalStore) Create(ctx context.Context, props *model.UsuarioCanal) error {
	query := "INSERT INTO usuario_canal (id_usuario, id_canal, data_hora) VALUES ($1, $2, $3)"
	_, err := s.db.ExecContext(ctx, query, props.UsuarioID, props.CanalID, props.DataHora)
	return err
}

func (s *usuarioCanalStore) Update(ctx context.Context, props *model.UsuarioCanal) error {
	query := "UPDATE usuario_canal SET data_hora = $1 WHERE id_usuario = $2 AND id_canal = $3"
	res, err := s.db.ExecContext(ctx, query, props.DataHora, props.UsuarioID, props.CanalID)
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

func (s *usuarioCanalStore) Delete(ctx context.Context, id_usuario int64, id_canal int64) (*model.UsuarioCanal, error) {
	usuario, err := s.GetByComposedID(ctx, id_usuario, id_canal)
	if err != nil {
		return nil, err
	}

	query := "DELETE FROM usuario_canal WHERE id_usuario = $1 AND id_canal = $2"
	res, err := s.db.ExecContext(ctx, query, usuario.UsuarioID, usuario.CanalID)
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

	return usuario, nil
}
