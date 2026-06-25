package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// setupMidiaTestDB inicializa um container Postgres com a tabela Midia criada.
// Retorna o storage e uma função de limpeza para ser chamada com defer
func setupMidiaTestDB(t *testing.T) (*PostgresStorage, func()) {
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

	// Cria a tabela Midia inline (equivalente à migration 000006_midia_table.up.sql)
	_, err = store.db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS Midia (
			id_midia     VARCHAR(255) NOT NULL,
			origin       VARCHAR(255) NOT NULL,
			content_type VARCHAR(255) NOT NULL,
			size_bytes   BIGINT       NOT NULL,
			upload_name  VARCHAR(255),
			id_usuario   VARCHAR(255) NOT NULL,
			created_at   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (origin, id_midia)
		)
	`)
	if err != nil {
		poolClose()
		container.Terminate(ctx)
		t.Fatalf("create Midia table: %v", err)
	}

	return store, func() {
		poolClose()
		container.Terminate(ctx)
	}
}

func TestSaveMidia(t *testing.T) {
	store, cleanup := setupMidiaTestDB(t)
	defer cleanup()

	midia := &domain.Midia{
		IDMidia:     "abc123def456abc1",
		Origin:      "example.com",
		ContentType: "image/png",
		SizeBytes:   2048,
		UploadName:  "avatar.png",
		IDUsuario:   "@alice:example.com",
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
	}

	if err := store.SaveMidia(context.Background(), midia); err != nil {
		t.Fatalf("SaveMidia returned error: %v", err)
	}

	// Verifica a persistência buscando pelo par (origin, id_midia)
	retrieved, err := store.GetMidiaByID(context.Background(), midia.Origin, midia.IDMidia)
	if err != nil {
		t.Fatalf("GetMidiaByID returned error: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected to find saved midia, got nil")
	}
	if retrieved.IDMidia != midia.IDMidia {
		t.Fatalf("expected id_midia %s, got %s", midia.IDMidia, retrieved.IDMidia)
	}
	if retrieved.Origin != midia.Origin {
		t.Fatalf("expected origin %s, got %s", midia.Origin, retrieved.Origin)
	}
	if retrieved.ContentType != midia.ContentType {
		t.Fatalf("expected content_type %s, got %s", midia.ContentType, retrieved.ContentType)
	}
	if retrieved.SizeBytes != midia.SizeBytes {
		t.Fatalf("expected size_bytes %d, got %d", midia.SizeBytes, retrieved.SizeBytes)
	}
	if retrieved.IDUsuario != midia.IDUsuario {
		t.Fatalf("expected id_usuario %s, got %s", midia.IDUsuario, retrieved.IDUsuario)
	}
}

func TestSaveMidiaDuplicateIDFails(t *testing.T) {
	// Inserir dois registros com o mesmo (origin, id_midia) deve violar a PK
	store, cleanup := setupMidiaTestDB(t)
	defer cleanup()

	midia := &domain.Midia{
		IDMidia:     "duplicate000000",
		Origin:      "example.com",
		ContentType: "text/plain",
		SizeBytes:   10,
		UploadName:  "file.txt",
		IDUsuario:   "@alice:example.com",
		CreatedAt:   time.Now().UTC(),
	}

	if err := store.SaveMidia(context.Background(), midia); err != nil {
		t.Fatalf("first SaveMidia should succeed, got %v", err)
	}

	if err := store.SaveMidia(context.Background(), midia); err == nil {
		t.Fatal("expected error on duplicate primary key, got nil")
	}
}

func TestGetMidiaByIDNotFound(t *testing.T) {
	// Buscar ID inexistente deve retornar nil, nil (não um erro)
	store, cleanup := setupMidiaTestDB(t)
	defer cleanup()

	result, err := store.GetMidiaByID(context.Background(), "example.com", "nonexistent")
	if err != nil {
		t.Fatalf("expected nil error for missing entry, got %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for missing entry, got %+v", result)
	}
}

func TestGetMidiaByIDCompositeKey(t *testing.T) {
	// Mesmo id_midia com origins diferentes são registros distintos
	store, cleanup := setupMidiaTestDB(t)
	defer cleanup()

	midiaA := &domain.Midia{
		IDMidia:     "sharedid1234567",
		Origin:      "server-a.com",
		ContentType: "image/jpeg",
		SizeBytes:   512,
		UploadName:  "photo.jpg",
		IDUsuario:   "@alice:server-a.com",
		CreatedAt:   time.Now().UTC(),
	}
	midiaB := &domain.Midia{
		IDMidia:     "sharedid1234567", // mesmo id_midia
		Origin:      "server-b.com",    // origin diferente → PK diferente
		ContentType: "video/mp4",
		SizeBytes:   8192,
		UploadName:  "clip.mp4",
		IDUsuario:   "@bob:server-b.com",
		CreatedAt:   time.Now().UTC(),
	}

	if err := store.SaveMidia(context.Background(), midiaA); err != nil {
		t.Fatalf("save midiaA: %v", err)
	}
	if err := store.SaveMidia(context.Background(), midiaB); err != nil {
		t.Fatalf("save midiaB: %v", err)
	}

	resultA, err := store.GetMidiaByID(context.Background(), "server-a.com", "sharedid1234567")
	if err != nil || resultA == nil {
		t.Fatalf("expected to find midiaA, got result=%v err=%v", resultA, err)
	}
	if resultA.ContentType != "image/jpeg" {
		t.Fatalf("expected midiaA content_type 'image/jpeg', got %s", resultA.ContentType)
	}

	resultB, err := store.GetMidiaByID(context.Background(), "server-b.com", "sharedid1234567")
	if err != nil || resultB == nil {
		t.Fatalf("expected to find midiaB, got result=%v err=%v", resultB, err)
	}
	if resultB.ContentType != "video/mp4" {
		t.Fatalf("expected midiaB content_type 'video/mp4', got %s", resultB.ContentType)
	}
}