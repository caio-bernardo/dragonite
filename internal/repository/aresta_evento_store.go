package repository

import (
	"context"
	"database/sql"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type ArestaEventoStore interface {
	GetAll(ctx context.Context, filter util.Filter) ([]model.ArestaEvento, error)
	GetByComposedID(ctx context.Context, eventoID string, eventoAntecessorID string) (*model.ArestaEvento, error)
	GetAllByEventoID(ctx context.Context, eventoID string) ([]model.ArestaEvento, error)
	GetAllByCanalID(ctx context.Context, canalID string) ([]model.ArestaEvento, error)
	Create(ctx context.Context, props *model.ArestaEvento) error
	Update(ctx context.Context, props *model.ArestaEvento) error
	Delete(ctx context.Context, eventoID string, eventoAntecessorID string) (*model.ArestaEvento, error)
}

type arestaEventoStore struct {
	db *sql.DB
}

func NewArestaEventoStore(db *sql.DB) ArestaEventoStore {
	return &arestaEventoStore{db}
}

func (s *arestaEventoStore) GetAll(ctx context.Context, filter util.Filter) ([]model.ArestaEvento, error) {
	query := "SELECT ae.fk_id_evento, ae.id_evento_antecessor, ae.fk_id_canal, ae.is_state FROM aresta_evento ae"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "ae")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	arestas := make([]model.ArestaEvento, 0)
	for rows.Next() {
		var ae model.ArestaEvento
		err = rows.Scan(&ae.EventoID, &ae.EventoAntecessorID, &ae.CanalID, &ae.IsState)
		if err != nil {
			return nil, err
		}
		arestas = append(arestas, ae)
	}
	return arestas, nil
}

func (s *arestaEventoStore) GetByComposedID(ctx context.Context, eventoID string, eventoAntecessorID string) (*model.ArestaEvento, error) {
	query := "SELECT fk_id_evento, id_evento_antecessor, fk_id_canal, is_state FROM aresta_evento WHERE fk_id_evento = $1 AND id_evento_antecessor = $2"
	row := s.db.QueryRowContext(ctx, query, eventoID, eventoAntecessorID)

	var ae model.ArestaEvento
	err := row.Scan(&ae.EventoID, &ae.EventoAntecessorID, &ae.CanalID, &ae.IsState)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &ae, nil
}

func (s *arestaEventoStore) GetAllByEventoID(ctx context.Context, eventoID string) ([]model.ArestaEvento, error) {
	query := "SELECT fk_id_evento, id_evento_antecessor, fk_id_canal, is_state FROM aresta_evento WHERE fk_id_evento = $1"
	rows, err := s.db.QueryContext(ctx, query, eventoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var arestas []model.ArestaEvento
	for rows.Next() {
		var ae model.ArestaEvento
		err = rows.Scan(&ae.EventoID, &ae.EventoAntecessorID, &ae.CanalID, &ae.IsState)
		if err != nil {
			return nil, err
		}
		arestas = append(arestas, ae)
	}
	return arestas, nil
}

func (s *arestaEventoStore) GetAllByCanalID(ctx context.Context, canalID string) ([]model.ArestaEvento, error) {
	query := "SELECT fk_id_evento, id_evento_antecessor, fk_id_canal, is_state FROM aresta_evento WHERE fk_id_canal = $1"
	rows, err := s.db.QueryContext(ctx, query, canalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var arestas []model.ArestaEvento
	for rows.Next() {
		var ae model.ArestaEvento
		err = rows.Scan(&ae.EventoID, &ae.EventoAntecessorID, &ae.CanalID, &ae.IsState)
		if err != nil {
			return nil, err
		}
		arestas = append(arestas, ae)
	}
	return arestas, nil
}

func (s *arestaEventoStore) Create(ctx context.Context, props *model.ArestaEvento) error {
	query := "INSERT INTO aresta_evento (fk_id_evento, id_evento_antecessor, fk_id_canal, is_state) VALUES ($1, $2, $3, $4)"
	_, err := s.db.ExecContext(ctx, query, props.EventoID, props.EventoAntecessorID, props.CanalID, props.IsState)
	return err
}

func (s *arestaEventoStore) Update(ctx context.Context, props *model.ArestaEvento) error {
	query := "UPDATE aresta_evento SET fk_id_canal = $1, is_state = $2 WHERE fk_id_evento = $3 AND id_evento_antecessor = $4"
	res, err := s.db.ExecContext(ctx, query, props.CanalID, props.IsState, props.EventoID, props.EventoAntecessorID)
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

func (s *arestaEventoStore) Delete(ctx context.Context, eventoID string, eventoAntecessorID string) (*model.ArestaEvento, error) {
	aresta, err := s.GetByComposedID(ctx, eventoID, eventoAntecessorID)
	if err != nil {
		return nil, err
	}

	query := "DELETE FROM aresta_evento WHERE fk_id_evento = $1 AND id_evento_antecessor = $2"
	res, err := s.db.ExecContext(ctx, query, aresta.EventoID, aresta.EventoAntecessorID)
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

	return aresta, nil
}
