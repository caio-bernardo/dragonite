package repository

import (
	"context"
	"database/sql"
	"fmt"

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
	// Adicionados para suporte às rotas Matrix de rooms
	ListPublic(ctx context.Context, limit int, sinceToken string) ([]model.Canal, string, error)
	UpdateMemberCount(ctx context.Context, canalID string, delta int) error
	UpsertEstadoAtual(ctx context.Context, estado *model.EstadoAtualCanal) error
}

type canalStore struct {
	db *sql.DB
}

func NewChannelStore(db *sql.DB) ChannelStore {
	return &canalStore{db}
}

// colunas em ordem usada em todos os SELECTs, centraliza para evitar dessincronias
const canalColumns = `
	id_canal, local_part, server_name, nome_canal, descricao_canal, foto_canal, 
	canonical_alias, is_public_canal, join_rules, guest_access, room_type, 
	versao_canal, fk_id_criador, member_count, history_visibility, data_criacao_canal`

func scanCanal(row interface{ Scan(...any) error }, c *model.Canal) error {
	return row.Scan(
		&c.ID, &c.LocalPart, &c.ServerName, &c.Nome, &c.Descricao, &c.Foto,
		&c.CanonAlias, &c.IsPublic, &c.JoinRules, &c.GuestAccess, &c.RoomType,
		&c.Versao, &c.CriadorID, &c.MemberCount, &c.HistoryVisibility, &c.DataCriacao,
	)
}

func (s *canalStore) GetAll(ctx context.Context, filter util.Filter) ([]model.Canal, error) {
	query := "SELECT" + canalColumns + " FROM canal c"

	rows, err := util.QueryRowsWithFilter(s.db, ctx, query, &filter, "c")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	canais := make([]model.Canal, 0)
	for rows.Next() {
		var c model.Canal
		if err := scanCanal(rows, &c); err != nil {
			return nil, err
		}
		canais = append(canais, c)
	}
	return canais, nil
}

func (s *canalStore) GetByID(ctx context.Context, id string) (*model.Canal, error) {
	query := `SELECT ` + canalColumns + ` FROM canal WHERE id_canal = $1`
	var c model.Canal
	err := scanCanal(s.db.QueryRowContext(ctx, query, id), &c)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, types.ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (s *canalStore) Create(ctx context.Context, props *model.Canal) error {
	query := `INSERT INTO canal (` + canalColumns + `) 
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`
	
	_, err := s.db.ExecContext(ctx, query,
		props.ID, props.LocalPart, props.ServerName, props.Nome, props.Descricao, props.Foto,
		props.CanonAlias, props.IsPublic, props.JoinRules, props.GuestAccess, props.RoomType,
		props.Versao, props.CriadorID, props.MemberCount, props.HistoryVisibility, props.DataCriacao,
	)
	return err
}

func (s *canalStore) Update(ctx context.Context, props *model.Canal) error {
	query := `
		UPDATE canal SET
			nome_canal = $1, descricao_canal = $2, foto_canal = $3,
			is_public_canal = $4, versao_canal = $5, fk_id_criador = $6,
			join_rules = $7, guest_access = $8, history_visibility = $9,
			data_criacao_canal = $10
		WHERE id_canal = $11`
	res, err := s.db.ExecContext(ctx, query,
		props.Nome, props.Descricao, props.Foto,
		props.IsPublic, props.Versao, props.CriadorID,
		props.JoinRules, props.GuestAccess, props.HistoryVisibility,
		props.DataCriacao, props.ID,
	)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return types.ErrNotFound
	}
	return nil
}

func (s *canalStore) Delete(ctx context.Context, id_canal string) (*model.Canal, error) {
	canal, err := s.GetByID(ctx, id_canal)
	if err != nil {
		return nil, err
	}

	for _, q := range []string{
		"DELETE FROM usuario_canal WHERE fk_id_canal = $1",
		"DELETE FROM estado_atual_canal WHERE fk_id_canal = $1",
		"DELETE FROM evento WHERE fk_id_canal = $1",
		"DELETE FROM canal WHERE id_canal = $1",
	} {
		res, err := s.db.ExecContext(ctx, q, canal.ID)
		if err != nil {
			return nil, err
		}
		// Só verifica rowsAffected no DELETE do canal em si
		if q == "DELETE FROM canal WHERE id_canal = $1" {
			affected, _ := res.RowsAffected()
			if affected == 0 {
				return nil, types.ErrNotFound
			}
		}
	}
	return canal, nil
}

func (s *canalStore) ListPublic(ctx context.Context, limit int, sinceToken string) ([]model.Canal, string, error) {
	offset := 0
	if sinceToken != "" {
		fmt.Sscanf(sinceToken, "%d", &offset)
	}

	query := "SELECT" + canalColumns + `
		FROM canal
		WHERE is_public_canal = true
		ORDER BY member_count DESC
		LIMIT $1 OFFSET $2`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	canais := make([]model.Canal, 0)
	for rows.Next() {
		var c model.Canal
		if err := scanCanal(rows, &c); err != nil {
			return nil, "", err
		}
		canais = append(canais, c)
	}

	nextBatch := ""
	if len(canais) == limit {
		nextBatch = fmt.Sprintf("%d", offset+limit)
	}
	return canais, nextBatch, rows.Err()
}

func (s *canalStore) UpdateMemberCount(ctx context.Context, canalID string, delta int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE canal SET member_count = member_count + $1 WHERE id_canal = $2`,
		delta, canalID,
	)
	return err
}

func (s *canalStore) UpsertEstadoAtual(ctx context.Context, estado *model.EstadoAtualCanal) error {
	query := `
		INSERT INTO estado_atual_canal (fk_id_canal, tipo, state_key, fk_id_evento)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (fk_id_canal, tipo, state_key)
		DO UPDATE SET fk_id_evento = EXCLUDED.fk_id_evento`

	_, err := s.db.ExecContext(ctx, query, estado.CanalID, estado.Tipo, estado.StateKey, estado.EventoID)
	return err
}
