package mensagem

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

func (s *Store) GetAll(ctx context.Context, filter util.Filter) ([]model.Mensagem, error) {
	query := "SELECT id_mensagem, texto_mensagem, data_hora, autor FROM mensagem"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "io")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	mensagens := make([]model.Mensagem, 0)
	for rows.Next() {
		var d model.Mensagem
		err = rows.Scan(&d.ID, &d.Texto, &d.DataHora, &d.Autor)
		if err != nil {
			return nil, err
		}
		mensagens = append(mensagens, d)
	}
	return mensagens, nil
}

func (s *Store) GetByID(ctx context.Context, id int64) (*model.Mensagem, error) {
	query := "SELECT id_mensagem, texto_mensagem, data_hora, autor FROM mensagem WHERE id_mensagem = $1;"
	row := s.db.QueryRowContext(ctx, query, id)

	var d model.Mensagem
	err := row.Scan(&d.ID, &d.Texto, &d.DataHora, &d.Autor)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

func (s *Store) Create(ctx context.Context, props *model.Mensagem) error {
	query := "INSERT INTO mensagem (id_mensagem, texto_mensagem, data_hora, autor) VALUES ($1, $2, $3, $4);"
	_, err := s.db.ExecContext(ctx, query, props.ID, props.Texto, props.DataHora, props.Autor)
	return err
}

func (s *Store) Update(ctx context.Context, props *model.Mensagem) error {
	query := "UPDATE mensagem SET texto_mensagem = $1, data_hora = $2, autor = $3 WHERE id_mensagem = $4"
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

func (s *Store) Delete(ctx context.Context, id_mensagem int64) (*model.Mensagem, error) {
	mensagem, err := s.GetByID(ctx, id_mensagem)
	if err != nil {
		return nil, err
	}

	query := "DELETE FROM mensagem WHERE id_mensagem = $1"
	res, err := s.db.ExecContext(ctx, query, mensagem.ID)
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

	return mensagem, nil
}
