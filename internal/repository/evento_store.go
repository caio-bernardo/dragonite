package repository

import (
	"context"
	"database/sql"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type EventoStore interface {
	GetAll(ctx context.Context, filter util.Filter) ([]model.Evento, error)
	GetByID(ctx context.Context, id string) (*model.Evento, error)
	Create(ctx context.Context, props *model.Evento) error
	Update(ctx context.Context, props *model.Evento) error
	Delete(ctx context.Context, id string) (*model.Evento, error)
}

type eventoStore struct {
	db *sql.DB
}

func NewEventoStore(db *sql.DB) EventoStore {
	return &eventoStore{db}
}

func (s *eventoStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Evento, error) {
	query := "SELECT e.id_evento, e.tipo_evento, e.fk_id_canal, e.fk_id_sender, e.state_key, e.conteudo_evento::text, e.origem_servidor_evento_ts, e.stream_ordering_evento FROM evento e"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "e")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	eventos := make([]model.Evento, 0)
	for rows.Next() {
		var e model.Evento
		err = rows.Scan(&e.ID, &e.Tipo, &e.CanalID, &e.SenderID, &e.StateKey, &e.Conteudo, &e.OrigemServidorTS, &e.StreamOrdering)
		if err != nil {
			return nil, err
		}
		eventos = append(eventos, e)
	}
	return eventos, nil
}

func (s *eventoStore) GetByID(ctx context.Context, id string) (*model.Evento, error) {
	query := "SELECT id_evento, tipo_evento, fk_id_canal, fk_id_sender, state_key, conteudo_evento::text, origem_servidor_evento_ts, stream_ordering_evento FROM evento WHERE id_evento = $1;"
	row := s.db.QueryRowContext(ctx, query, id)

	var e model.Evento
	err := row.Scan(&e.ID, &e.Tipo, &e.CanalID, &e.SenderID, &e.StateKey, &e.Conteudo, &e.OrigemServidorTS, &e.StreamOrdering)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &e, nil
}

func (s *eventoStore) Create(ctx context.Context, props *model.Evento) error {
	query := "INSERT INTO evento (id_evento, tipo_evento, fk_id_canal, fk_id_sender, state_key, conteudo_evento, origem_servidor_evento_ts, stream_ordering_evento) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8);"
	_, err := s.db.ExecContext(ctx, query, props.ID, props.Tipo, props.CanalID, props.SenderID, props.StateKey, props.Conteudo, props.OrigemServidorTS, props.StreamOrdering)
	return err
}

func (s *eventoStore) Update(ctx context.Context, props *model.Evento) error {
	query := "UPDATE evento SET tipo_evento = $1, fk_id_canal = $2, fk_id_sender = $3, state_key = $4, conteudo_evento = $5::jsonb, origem_servidor_evento_ts = $6, stream_ordering_evento = $7 WHERE id_evento = $8"
	res, err := s.db.ExecContext(ctx, query, props.Tipo, props.CanalID, props.SenderID, props.StateKey, props.Conteudo, props.OrigemServidorTS, props.StreamOrdering, props.ID)
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

func (s *eventoStore) Delete(ctx context.Context, id string) (*model.Evento, error) {
	evento, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	_, err = s.db.ExecContext(ctx, "DELETE FROM usuario_canal WHERE fk_id_evento = $1", evento.ID)
	if err != nil {
		return nil, err
	}

	_, err = s.db.ExecContext(ctx, "DELETE FROM estado_atual_canal WHERE fk_id_evento = $1", evento.ID)
	if err != nil {
		return nil, err
	}

	query := "DELETE FROM evento WHERE id_evento = $1"
	res, err := s.db.ExecContext(ctx, query, evento.ID)
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

	return evento, nil
}
