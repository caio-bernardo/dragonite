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
	GetByComposedID(ctx context.Context, id_usuario string, id_canal string) (*model.UsuarioCanal, error)
	GetAllByUsuarioID(ctx context.Context, id_usuario string) ([]model.UsuarioCanal, error)
	GetAllByCanalID(ctx context.Context, id_canal string) ([]model.UsuarioCanal, error)
	Create(ctx context.Context, props *model.UsuarioCanal) error
	Update(ctx context.Context, props *model.UsuarioCanal) error
	Delete(ctx context.Context, id_usuario string, id_canal string) (*model.UsuarioCanal, error)
}

type usuarioCanalStore struct {
	db *sql.DB
}

func NewUsuarioCanalStore(db *sql.DB) UsuarioCanalStore {
	return &usuarioCanalStore{db}
}

func (s *usuarioCanalStore) GetAll(ctx context.Context, filter util.Filter) ([]model.UsuarioCanal, error) {
	query := "SELECT uc.fk_id_canal, uc.fk_id_usuario, uc.fk_id_evento, uc.membresia FROM usuario_canal uc"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "uc")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	usuarios := make([]model.UsuarioCanal, 0)
	for rows.Next() {
		var d model.UsuarioCanal
		err = rows.Scan(&d.CanalID, &d.UsuarioID, &d.EventoID, &d.Membresia)
		if err != nil {
			return nil, err
		}
		usuarios = append(usuarios, d)
	}
	return usuarios, nil
}

// GetByComposedID busca uma entrada específica de ItemOferta pela sua chave primária composta.
func (s *usuarioCanalStore) GetByComposedID(ctx context.Context, id_usuario string, id_canal string) (*model.UsuarioCanal, error) {
	query := "SELECT fk_id_canal, fk_id_usuario, fk_id_evento, membresia FROM usuario_canal WHERE fk_id_usuario = $1 AND fk_id_canal = $2"
	row := s.db.QueryRowContext(ctx, query, id_usuario, id_canal)

	var io model.UsuarioCanal
	err := row.Scan(&io.CanalID, &io.UsuarioID, &io.EventoID, &io.Membresia)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &io, nil
}

// GetAllByUsuarioID busca todas as entradas de UsuarioCanal para um determinado usuário.
func (s *usuarioCanalStore) GetAllByUsuarioID(ctx context.Context, id_usuario string) ([]model.UsuarioCanal, error) {
	query := "SELECT fk_id_canal, fk_id_usuario, fk_id_evento, membresia FROM usuario_canal WHERE fk_id_usuario = $1"
	rows, err := s.db.QueryContext(ctx, query, id_usuario)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usuariosCanal []model.UsuarioCanal
	for rows.Next() {
		var uc model.UsuarioCanal
		err = rows.Scan(&uc.CanalID, &uc.UsuarioID, &uc.EventoID, &uc.Membresia)
		if err != nil {
			return nil, err
		}
		usuariosCanal = append(usuariosCanal, uc)
	}
	return usuariosCanal, nil
}

// GetAllByCanalID busca todas as entradas de UsuarioCanal para um determinado canal.
func (s *usuarioCanalStore) GetAllByCanalID(ctx context.Context, id_canal string) ([]model.UsuarioCanal, error) {
	query := "SELECT fk_id_canal, fk_id_usuario, fk_id_evento, membresia FROM usuario_canal WHERE fk_id_canal = $1"
	rows, err := s.db.QueryContext(ctx, query, id_canal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usuariosCanal []model.UsuarioCanal
	for rows.Next() {
		var uc model.UsuarioCanal
		err = rows.Scan(&uc.CanalID, &uc.UsuarioID, &uc.EventoID, &uc.Membresia)
		if err != nil {
			return nil, err
		}
		usuariosCanal = append(usuariosCanal, uc)
	}
	return usuariosCanal, nil
}

func (s *usuarioCanalStore) Create(ctx context.Context, props *model.UsuarioCanal) error {
	query := "INSERT INTO usuario_canal (fk_id_canal, fk_id_usuario, fk_id_evento, membresia) VALUES ($1, $2, $3, $4)"
	_, err := s.db.ExecContext(ctx, query, props.CanalID, props.UsuarioID, props.EventoID, props.Membresia)
	return err
}

func (s *usuarioCanalStore) Update(ctx context.Context, props *model.UsuarioCanal) error {
	query := "UPDATE usuario_canal SET fk_id_evento = $1, membresia = $2 WHERE fk_id_canal = $3 AND fk_id_usuario = $4"
	res, err := s.db.ExecContext(ctx, query, props.EventoID, props.Membresia, props.CanalID, props.UsuarioID)
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

func (s *usuarioCanalStore) Delete(ctx context.Context, id_usuario string, id_canal string) (*model.UsuarioCanal, error) {
	usuario, err := s.GetByComposedID(ctx, id_usuario, id_canal)
	if err != nil {
		return nil, err
	}

	query := "DELETE FROM usuario_canal WHERE fk_id_usuario = $1 AND fk_id_canal = $2"
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
