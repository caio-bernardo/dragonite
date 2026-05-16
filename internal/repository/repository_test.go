package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var testDB *sql.DB

var baseTime = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS usuario (
	id_usuario VARCHAR(512) PRIMARY KEY,
	localpart_usuario VARCHAR(255) NOT NULL UNIQUE,
	senha_usuario VARCHAR(255) NOT NULL,
	nome_usuario VARCHAR(255),
	foto_usuario VARCHAR(255),
	data_criacao_usuario TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS canal (
	id_canal            VARCHAR(512) PRIMARY KEY,
    local_part          VARCHAR(255),
    server_name         VARCHAR(255),
    nome_canal          VARCHAR(50)  NOT NULL,
    descricao_canal     TEXT,
    foto_canal          TEXT,
    canonical_alias     VARCHAR(512),
    is_public_canal     BOOLEAN      NOT NULL DEFAULT FALSE,
    join_rules          VARCHAR(50)  NOT NULL DEFAULT 'invite',
    guest_access        VARCHAR(50)  NOT NULL DEFAULT 'forbidden',
    versao_canal        VARCHAR(50)  DEFAULT '1',
    fk_id_criador       VARCHAR(512) NOT NULL REFERENCES usuario(id_usuario),
    member_count        INTEGER      NOT NULL DEFAULT 0,
    room_type           VARCHAR(255),
    history_visibility  VARCHAR(50)  NOT NULL DEFAULT 'shared',
    data_criacao_canal  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evento (
	id_evento VARCHAR(512) PRIMARY KEY,
	tipo_evento VARCHAR(255) NOT NULL,
	fk_id_canal VARCHAR(512) NOT NULL REFERENCES canal(id_canal),
	fk_id_sender VARCHAR(512) NOT NULL REFERENCES usuario(id_usuario),
	state_key VARCHAR(255),
	conteudo_evento JSONB NOT NULL,
	origem_servidor_evento_ts BIGINT NOT NULL,
	stream_ordering_evento BIGSERIAL UNIQUE NOT NULL,
	txn_id VARCHAR(255),
    CONSTRAINT uq_evento_sender_txn UNIQUE (fk_id_sender, txn_id)
);

CREATE TABLE IF NOT EXISTS aresta_evento (
	fk_id_evento VARCHAR(512) NOT NULL REFERENCES evento(id_evento) ON DELETE CASCADE,
	id_evento_antecessor VARCHAR(512) NOT NULL,
	fk_id_canal VARCHAR(512) NOT NULL REFERENCES canal(id_canal),
	is_state BOOLEAN DEFAULT FALSE,
	PRIMARY KEY (fk_id_evento, id_evento_antecessor)
);

CREATE TABLE IF NOT EXISTS estado_atual_canal (
	fk_id_canal VARCHAR(512) NOT NULL REFERENCES canal(id_canal),
	tipo VARCHAR(255) NOT NULL,
	state_key VARCHAR(255) NOT NULL,
	fk_id_evento VARCHAR(512) NOT NULL REFERENCES evento(id_evento),
	PRIMARY KEY (fk_id_canal, tipo, state_key)
);

CREATE TABLE IF NOT EXISTS usuario_canal (
	fk_id_canal VARCHAR(512) NOT NULL REFERENCES canal(id_canal),
	fk_id_usuario VARCHAR(512) NOT NULL REFERENCES usuario(id_usuario),
	fk_id_evento VARCHAR(512) REFERENCES evento(id_evento),
	membresia VARCHAR(50) NOT NULL,
	joined_at     TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (fk_id_canal, fk_id_usuario)
	
);

CREATE TABLE IF NOT EXISTS dispositivo (
	id_dispositivo UUID PRIMARY KEY,
	fk_id_usuario VARCHAR(512) NOT NULL REFERENCES usuario(id_usuario) ON DELETE CASCADE,
	nome_dispositivo VARCHAR(255),
	refresh_token VARCHAR(64) NOT NULL UNIQUE,
	refresh_token_expires_at TIMESTAMP WITH TIME ZONE,
	ultimo_ip_visto VARCHAR(50),
	ultimo_timestamp_visto TIMESTAMP WITH TIME ZONE
);
`

func TestMain(m *testing.M) {
	ctx := context.Background()

	dbName := "repository_test"
	dbUser := "user"
	dbPwd := "password"

	dbContainer, err := postgres.Run(
		ctx,
		"postgres:latest",
		postgres.WithDatabase(dbName),
		postgres.WithUsername(dbUser),
		postgres.WithPassword(dbPwd),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		log.Fatalf("could not start postgres container: %v", err)
	}

	dbHost, err := dbContainer.Host(ctx)
	if err != nil {
		log.Fatalf("could not get postgres host: %v", err)
	}

	dbPort, err := dbContainer.MappedPort(ctx, "5432/tcp")
	if err != nil {
		log.Fatalf("could not get postgres port: %v", err)
	}

	connStr := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser,
		dbPwd,
		dbHost,
		dbPort.Port(),
		dbName,
	)

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatalf("could not open database connection: %v", err)
	}
	testDB = db

	if err := applySchema(ctx, db); err != nil {
		log.Fatalf("could not apply schema: %v", err)
	}

	code := m.Run()

	if err := db.Close(); err != nil {
		log.Printf("could not close database: %v", err)
	}

	if err := dbContainer.Terminate(ctx); err != nil {
		log.Printf("could not teardown postgres container: %v", err)
	}

	os.Exit(code)
}

func applySchema(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, schemaSQL)
	return err
}

func resetTables(t *testing.T) {
	t.Helper()
	_, err := testDB.Exec(`
		TRUNCATE usuario_canal, estado_atual_canal, aresta_evento, evento, dispositivo, canal, usuario
		RESTART IDENTITY CASCADE;
	`)
	if err != nil {
		t.Fatalf("failed to reset tables: %v", err)
	}
}

func insertUsuario(t *testing.T, user model.Usuario) {
	t.Helper()
	_, err := testDB.Exec(
		`INSERT INTO usuario (id_usuario, localpart_usuario, senha_usuario, nome_usuario, foto_usuario, data_criacao_usuario)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		user.ID, user.LocalPart, user.Senha, user.Nome, user.Foto, user.DataCriacao,
	)
	if err != nil {
		t.Fatalf("failed to insert usuario: %v", err)
	}
}

func insertCanal(t *testing.T, canal model.Canal) {
	t.Helper()
	_, err := testDB.Exec(
		`INSERT INTO canal (id_canal, nome_canal, descricao_canal, foto_canal, is_public_canal, versao_canal, fk_id_criador, data_criacao_canal)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		canal.ID, canal.Nome, canal.Descricao, canal.Foto, canal.IsPublic, canal.Versao, canal.CriadorID, canal.DataCriacao,
	)
	if err != nil {
		t.Fatalf("failed to insert canal: %v", err)
	}
}

func insertEvento(t *testing.T, evento model.Evento) {
	t.Helper()
	_, err := testDB.Exec(
		`INSERT INTO evento (id_evento, tipo_evento, fk_id_canal, fk_id_sender, state_key, conteudo_evento, origem_servidor_evento_ts)
		 VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`,
		evento.ID, evento.Tipo, evento.CanalID, evento.SenderID, evento.StateKey, evento.Conteudo, evento.OrigemServidorTS,
	)
	if err != nil {
		t.Fatalf("failed to insert evento: %v", err)
	}
}

func insertArestaEvento(t *testing.T, aresta model.ArestaEvento) {
	t.Helper()
	_, err := testDB.Exec(
		`INSERT INTO aresta_evento (fk_id_evento, id_evento_antecessor, fk_id_canal, is_state)
		 VALUES ($1, $2, $3, $4)`,
		aresta.EventoID, aresta.EventoAntecessorID, aresta.CanalID, aresta.IsState,
	)
	if err != nil {
		t.Fatalf("failed to insert aresta_evento: %v", err)
	}
}

func insertUsuarioCanal(t *testing.T, uc model.UsuarioCanal) {
	t.Helper()
	_, err := testDB.Exec(
		`INSERT INTO usuario_canal (fk_id_canal, fk_id_usuario, fk_id_evento, membresia)
		 VALUES ($1, $2, $3, $4)`,
		uc.CanalID, uc.UsuarioID, uc.EventoID, uc.Membresia,
	)
	if err != nil {
		t.Fatalf("failed to insert usuario_canal: %v", err)
	}
}

func insertEstadoAtualCanal(t *testing.T, canalID, tipo, stateKey, eventoID string) {
	t.Helper()
	_, err := testDB.Exec(
		`INSERT INTO estado_atual_canal (fk_id_canal, tipo, state_key, fk_id_evento)
		 VALUES ($1, $2, $3, $4)`,
		canalID, tipo, stateKey, eventoID,
	)
	if err != nil {
		t.Fatalf("failed to insert estado_atual_canal: %v", err)
	}
}
