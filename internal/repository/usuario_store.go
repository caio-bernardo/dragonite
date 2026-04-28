package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
	"github.com/jackc/pgx/v5/pgconn"
)

type UserStore interface {
	GetAll(ctx context.Context, filter util.Filter) ([]model.Usuario, error)
	GetByID(ctx context.Context, id string) (*model.Usuario, error)
	GetByLocal(ctx context.Context, localpart string) (*model.Usuario, error)
	Create(ctx context.Context, usuario *model.Usuario) error
	Update(ctx context.Context, usuario *model.Usuario) error
	Delete(ctx context.Context, id string) (*model.Usuario, error)
	Search(ctx context.Context, term string, limit int) ([]model.Usuario, error)
}

type usuarioStore struct {
	db *sql.DB
}

func NewUsuarioStore(db *sql.DB) UserStore {
	return &usuarioStore{db}
}

func (s *usuarioStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Usuario, error) {
	query := "SELECT u.id_usuario, u.localpart_usuario, u.nome_usuario, u.senha_usuario, u.foto_usuario, u.data_criacao_usuario FROM usuario u"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "u")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	usuarios := make([]model.Usuario, 0)
	for rows.Next() {
		var d model.Usuario
		err = rows.Scan(&d.ID, &d.LocalPart, &d.Nome, &d.Senha, &d.Foto, &d.DataCriacao)
		if err != nil {
			return nil, err
		}
		usuarios = append(usuarios, d)
	}
	return usuarios, nil
}

func (s *usuarioStore) GetByID(ctx context.Context, id string) (*model.Usuario, error) {
	query := "SELECT id_usuario, nome_usuario, localpart_usuario, senha_usuario, foto_usuario, data_criacao_usuario FROM usuario WHERE id_usuario = $1;"
	row := s.db.QueryRowContext(ctx, query, id)

	var d model.Usuario
	err := row.Scan(&d.ID, &d.Nome, &d.LocalPart, &d.Senha, &d.Foto, &d.DataCriacao)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

// GetByLocal implements [UserStore].
func (s *usuarioStore) GetByLocal(ctx context.Context, localpart string) (*model.Usuario, error) {
	query := "SELECT id_usuario, nome_usuario, localpart_usuario, senha_usuario, foto_usuario, data_criacao_usuario FROM usuario WHERE localpart_usuario = $1;"
	row := s.db.QueryRowContext(ctx, query, localpart)

	var d model.Usuario
	err := row.Scan(&d.ID, &d.Nome, &d.LocalPart, &d.Senha, &d.Foto, &d.DataCriacao)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

func (s *usuarioStore) Create(ctx context.Context, props *model.Usuario) error {
	query := "INSERT INTO usuario (id_usuario, nome_usuario, localpart_usuario, senha_usuario, foto_usuario, data_criacao_usuario) VALUES ($1, $2, $3, $4, $5, $6);"
	_, err := s.db.ExecContext(ctx, query, props.ID, props.Nome, props.LocalPart, props.Senha, props.Foto, props.DataCriacao)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && strings.Contains(pgErr.ConstraintName, "localpart_usuario") {
			return types.ErrLocalpartInUse
		}
		return err
	}

	return nil
}

func (s *usuarioStore) Update(ctx context.Context, props *model.Usuario) error {
	query := "UPDATE usuario SET nome_usuario = $1, localpart_usuario = $2, senha_usuario = $3, foto_usuario = $4, data_criacao_usuario = $5 WHERE id_usuario = $6"
	res, err := s.db.ExecContext(ctx, query, props.Nome, props.LocalPart, props.Senha, props.Foto, props.DataCriacao, props.ID)
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

func (s *usuarioStore) Delete(ctx context.Context, id_usuario string) (*model.Usuario, error) {
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

// Search busca usuários por user_id ou nome de exibição de forma case-insensitive.

// NOTA: A spec Matrix exige que a busca considere apenas usuários "visíveis"
// para o solicitante, ou seja: usuários que compartilham uma sala com ele,
// usuários em salas públicas, ou em salas com histórico world_readable.
// Esta implementação ainda não aplica esse filtro de visibilidade — ela
// retorna todos os usuários locais que correspondem ao termo de busca.
// TODO: adicionar joins com as tabelas de salas (canal) e membros para respeitar
// a visibilidade conforme a spec.
func (s *usuarioStore) Search(ctx context.Context, term string, limit int) ([]model.Usuario, error) {
    query := `
        SELECT id_usuario, nome_usuario, localpart_usuario, foto_usuario
        FROM usuario
        WHERE LOWER(id_usuario) LIKE LOWER($1)
           OR LOWER(nome_usuario) LIKE LOWER($1)
        LIMIT $2`

    pattern := "%" + term + "%"
    rows, err := s.db.QueryContext(ctx, query, pattern, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    usuarios := make([]model.Usuario, 0)
    for rows.Next() {
        var u model.Usuario
        err = rows.Scan(&u.ID, &u.Nome, &u.LocalPart, &u.Foto)
        if err != nil {
            return nil, err
        }
        usuarios = append(usuarios, u)
    }
    return usuarios, nil
}