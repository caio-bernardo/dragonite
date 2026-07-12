package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func setupSyncStorageTestDB(t *testing.T) (*PostgresStorage, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("dragonite"),
		tcpostgres.WithUsername("dragonite"),
		tcpostgres.WithPassword("dragonite"),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("connection string: %v", err)
	}

	var poolClose func()
	var store *PostgresStorage
	deadline := time.Now().Add(15 * time.Second)
	for {
		pool, err := ConnectBD(ctx, connStr)
		if err == nil {
			poolClose = pool.Close
			store = NewPostgresStorage(pool)
			break
		}
		if time.Now().After(deadline) {
			container.Terminate(ctx)
			t.Fatalf("connect db: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	_, err = store.db.Exec(ctx, `
		CREATE TABLE Usuario (
			id_usuario VARCHAR(512) PRIMARY KEY
		);

		CREATE TABLE AccountData (
			fk_id_usuario VARCHAR(512) NOT NULL,
			id_canal VARCHAR(255) DEFAULT '',
			tipo VARCHAR(255) NOT NULL,
			content JSONB NOT NULL,
			PRIMARY KEY (fk_id_usuario, id_canal, tipo)
		);

		CREATE TABLE Evento (
			id_evento VARCHAR(255) PRIMARY KEY,
			tipo VARCHAR(255) NOT NULL,
			id_canal VARCHAR(255) NOT NULL,
			sender VARCHAR(255) NOT NULL,
			origin_server_ts BIGINT NOT NULL,
			content JSONB NOT NULL,
			stream_ordering BIGSERIAL NOT NULL,
			state_key VARCHAR(255)
		);

		CREATE TABLE Canal_Membership (
			id_canal VARCHAR(255) NOT NULL,
			id_usuario VARCHAR(255) NOT NULL,
			membership_type VARCHAR(50) NOT NULL,
			id_evento VARCHAR(255) NOT NULL,
			PRIMARY KEY (id_canal, id_usuario)
		);
	`)
	if err != nil {
		poolClose()
		container.Terminate(ctx)
		t.Fatalf("create sync tables: %v", err)
	}

	return store, func() {
		poolClose()
		container.Terminate(ctx)
	}
}

func TestPostgresSyncMethods(t *testing.T) {
	ctx := context.Background()
	store, cleanup := setupSyncStorageTestDB(t)
	defer cleanup()

	const userID = "@alice:example.com"
	const joinRoom = "!join:example.com"
	const inviteRoom = "!invite:example.com"
	const leftRoom = "!left:example.com"

	_, err := store.db.Exec(ctx, "INSERT INTO Usuario (id_usuario) VALUES ($1)", userID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	_, err = store.db.Exec(ctx, `
		INSERT INTO AccountData (fk_id_usuario, id_canal, tipo, content) VALUES
			($1, '', 'm.push_rules', '{"global":true}'),
			($1, $2, 'm.tag', '{"favourite":true}')
	`, userID, joinRoom)
	if err != nil {
		t.Fatalf("insert account data: %v", err)
	}

	_, err = store.db.Exec(ctx, `
		INSERT INTO Evento (id_evento, tipo, id_canal, sender, origin_server_ts, content, state_key) VALUES
			('evt_invite', 'm.room.member', $1, '@bob:example.com', 1000, '{"membership":"invite"}', $2),
			('evt_join_1', 'm.room.message', $3, '@bob:example.com', 1100, '{"body":"hello"}', NULL),
			('evt_left_1', 'm.room.message', $4, '@bob:example.com', 1200, '{"body":"bye"}', NULL),
			('evt_join_2', 'm.room.message', $3, '@bob:example.com', 1300, '{"body":"again"}', NULL)
	`, inviteRoom, userID, joinRoom, leftRoom)
	if err != nil {
		t.Fatalf("insert events: %v", err)
	}

	_, err = store.db.Exec(ctx, `
		INSERT INTO Canal_Membership (id_canal, id_usuario, membership_type, id_evento) VALUES
			($1, $4, 'invite', 'evt_invite'),
			($2, $4, 'join',   'evt_join_1'),
			($3, $4, 'leave',  'evt_left_1')
	`, inviteRoom, joinRoom, leftRoom, userID)
	if err != nil {
		t.Fatalf("insert memberships: %v", err)
	}

	accData, err := store.GetAccountDataOfCanal(ctx, userID, joinRoom)
	if err != nil {
		t.Fatalf("GetAccountDataOfCanal returned error: %v", err)
	}
	if len(accData) != 1 || accData[0].IDCanal != joinRoom {
		t.Fatalf("expected 1 room account data row for %s, got %+v", joinRoom, accData)
	}

	inviteEvents, err := store.GetInviteEventsSince(ctx, userID, domain.SyncToken{})
	if err != nil {
		t.Fatalf("GetInviteEventsSince returned error: %v", err)
	}
	if len(inviteEvents) != 1 || inviteEvents[0].ID != "evt_invite" {
		t.Fatalf("expected invite event evt_invite, got %+v", inviteEvents)
	}

	var inviteSO int64
	if err := store.db.QueryRow(ctx, "SELECT stream_ordering FROM Evento WHERE id_evento = 'evt_invite'").Scan(&inviteSO); err != nil {
		t.Fatalf("query invite stream ordering: %v", err)
	}
	inviteEvents, err = store.GetInviteEventsSince(ctx, userID, domain.SyncToken{TimelinePosition: inviteSO})
	if err != nil {
		t.Fatalf("GetInviteEventsSince with since returned error: %v", err)
	}
	if len(inviteEvents) != 0 {
		t.Fatalf("expected no invite events after since token, got %+v", inviteEvents)
	}

	leftRooms, err := store.GetUserLeftRooms(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserLeftRooms returned error: %v", err)
	}
	if len(leftRooms) != 1 || leftRooms[0] != leftRoom {
		t.Fatalf("expected left room %s, got %+v", leftRoom, leftRooms)
	}

	joinEvents, err := store.GetEventsOfCanalSince(ctx, userID, joinRoom, domain.SyncToken{})
	if err != nil {
		t.Fatalf("GetEventsOfCanalSince returned error: %v", err)
	}
	if len(joinEvents) != 2 {
		t.Fatalf("expected 2 join-room events, got %+v", joinEvents)
	}

	joinEvents, err = store.GetEventsOfCanalSince(ctx, userID, leftRoom, domain.SyncToken{})
	if err != nil {
		t.Fatalf("GetEventsOfCanalSince on left room returned error: %v", err)
	}
	if len(joinEvents) != 0 {
		t.Fatalf("expected no join-visible events for left room, got %+v", joinEvents)
	}

	leftEvents, err := store.GetEventsOfCanalSinceLeft(ctx, userID, leftRoom, domain.SyncToken{})
	if err != nil {
		t.Fatalf("GetEventsOfCanalSinceLeft returned error: %v", err)
	}
	if len(leftEvents) != 1 || leftEvents[0].ID != "evt_left_1" {
		t.Fatalf("expected left-room event evt_left_1, got %+v", leftEvents)
	}
}
