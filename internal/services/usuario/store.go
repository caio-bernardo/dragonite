package usuario

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

func (s *Store) GetAll(ctx context.Context, filter util.Filter) ([]model.Usuario, error) {
	query := "SELECT id_usuario, nome_usuario, email_usuario, senha_usuario, token_usuario, foto_usuario, host_usuario, data_criacao_usuario FROM usuario"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "io")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	usuarios := make([]model.Usuario, 0)
	for rows.Next() {
		var d model.Usuario
		err = rows.Scan(&d.ID, &d.Nome, &d.Email, &d.Senha, &d.Token, &d.Foto, &d.Host, &d.DataCriacao)
		if err != nil {
			return nil, err
		}
		usuarios = append(usuarios, d)
	}
	return usuarios, nil
}

func (s *Store) GetByID(ctx context.Context, id int64) (*model.Usuario, error) {
	query := "SELECT id_usuario, nome_usuario, email_usuario, senha_usuario, token_usuario, foto_usuario, host_usuario, data_criacao_usuario FROM usuario WHERE id_usuario = $1;"
	row := s.db.QueryRowContext(ctx, query, id)

	var d model.Usuario
	err := row.Scan(&d.ID, &d.Nome, &d.Email, &d.Senha, &d.Token, &d.Foto, &d.Host, &d.DataCriacao)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

func (s *Store) Create(ctx context.Context, props *model.Usuario) error {
	query := "INSERT INTO usuario (id_usuario, nome_usuario, email_usuario, senha_usuario, token_usuario, foto_usuario, host_usuario, data_criacao_usuario) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);"
	_, err := s.db.ExecContext(ctx, query, props.ID, props.Nome, props.Email, props.Senha, props.Token, props.Foto, props.Host, props.DataCriacao)
	return err
}

func (s *Store) Update(ctx context.Context, props *model.Usuario) error {
	query := "UPDATE usuario SET nome_usuario = $1, email_usuario = $2, senha_usuario = $3, token_usuario = $4, foto_usuario = $5, host_usuario = $6, data_criacao_usuario = $7 WHERE id_usuario = $8"
	res, err := s.db.ExecContext(ctx, query, props.Texto, props.DataHora, props.Autor, props.ID)
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

func (s *Store) Delete(ctx context.Context, id_usuario int64) (*model.Usuario, error) {
	usuario, err := s.GetByID(ctx, id_usuario)
	if err != nil {
		return nil, err
	}

	query := "DELETE FROM usuario WHERE id_usuario = $1"
	res, err := s.db.ExecContext(ctx, query, usuario.ID)
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
