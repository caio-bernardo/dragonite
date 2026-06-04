package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	
	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

// ListPublicParams encapsula todos os parâmetros de busca de canais públicos
type ListPublicParams struct {
    Limit      int       // 0 = sem limite
    SinceToken string    // token opaco de paginação (encoda offset)
    SearchTerm string    // vazio = sem filtro de texto
    RoomTypes  []*string // nil = sem filtro; nil dentro do slice = salas sem tipo
}

type ChannelStore interface {
	GetAll(ctx context.Context, filter util.Filter) ([]model.Canal, error)
	GetByID(ctx context.Context, id string) (*model.Canal, error)
	Create(ctx context.Context, props *model.Canal) error
	Update(ctx context.Context, props *model.Canal) error
	Delete(ctx context.Context, id_canal string) (*model.Canal, error)
	// Adicionados para suporte às rotas Matrix de rooms
	ListPublic(ctx context.Context, params ListPublicParams) (canais []model.Canal, nextBatch string, prevBatch string, total int, err error)
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

func (s *canalStore) ListPublic(ctx context.Context, params ListPublicParams) ([]model.Canal, string, string, int, error) {
    offset := 0
    if params.SinceToken != "" {
        fmt.Sscanf(params.SinceToken, "%d", &offset)
    }

    // Constrói WHERE dinamicamente
    conditions := []string{"is_public_canal = true"}
    args := []any{}

    if params.SearchTerm != "" {
        n := len(args) + 1
        conditions = append(conditions, fmt.Sprintf(
            "(nome_canal ILIKE $%d OR descricao_canal ILIKE $%d OR canonical_alias ILIKE $%d)",
            n, n, n,
        ))
        args = append(args, "%"+params.SearchTerm+"%")
    }

    if params.RoomTypes != nil {
        var typeConds []string
        for _, rt := range params.RoomTypes {
            if rt == nil {
                typeConds = append(typeConds, "room_type IS NULL")
            } else {
                n := len(args) + 1
                typeConds = append(typeConds, fmt.Sprintf("room_type = $%d", n))
                args = append(args, *rt)
            }
        }
        if len(typeConds) > 0 {
            conditions = append(conditions, "("+strings.Join(typeConds, " OR ")+")")
        }
    }

    where := "WHERE " + strings.Join(conditions, " AND ")

    // Contagem total
    var total int
    if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM canal "+where, args...).Scan(&total); err != nil {
        return nil, "", "", 0, err
    }

    // Query de dados com paginação
    dataArgs := make([]any, len(args))
    copy(dataArgs, args)

    var limitClause string
    if params.Limit > 0 {
        dataArgs = append(dataArgs, params.Limit, offset)
        limitClause = fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(dataArgs)-1, len(dataArgs))
    } else {
        dataArgs = append(dataArgs, offset)
        limitClause = fmt.Sprintf(" OFFSET $%d", len(dataArgs))
    }

    dataQuery := "SELECT" + canalColumns + " FROM canal " + where +
        " ORDER BY member_count DESC" + limitClause

    rows, err := s.db.QueryContext(ctx, dataQuery, dataArgs...)
    if err != nil {
        return nil, "", "", 0, err
    }
    defer rows.Close()

    canais := make([]model.Canal, 0)
    for rows.Next() {
        var c model.Canal
        if err := scanCanal(rows, &c); err != nil {
            return nil, "", "", 0, err
        }
        canais = append(canais, c)
    }
    if err := rows.Err(); err != nil {
        return nil, "", "", 0, err
    }

    // Tokens de paginação
    nextBatch := ""
    if params.Limit > 0 && len(canais) == params.Limit {
        nextBatch = fmt.Sprintf("%d", offset+params.Limit)
    }
    prevBatch := ""
    if offset > 0 && params.Limit > 0 {
        if prev := offset - params.Limit; prev >= 0 {
            prevBatch = fmt.Sprintf("%d", prev)
        }
    }

    return canais, nextBatch, prevBatch, total, nil
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
