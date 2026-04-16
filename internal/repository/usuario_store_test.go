package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

func TestUsuarioStoreCRUDAndLookups(t *testing.T) {
	resetTables(t)

	store := NewUsuarioStore(testDB)
	ctx := context.Background()

	user := model.Usuario{
		ID:          "@alice:example.com",
		LocalPart:   "alice",
		Nome:        "Alice",
		Senha:       "secret",
		Foto:        "https://example.com/alice.png",
		DataCriacao: baseTime,
	}

	if err := store.Create(ctx, &user); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	got, err := store.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID() failed: %v", err)
	}
	if got.ID != user.ID || got.LocalPart != user.LocalPart || got.Nome != user.Nome || got.Senha != user.Senha || got.Foto != user.Foto || !got.DataCriacao.Equal(user.DataCriacao) {
		t.Fatalf("GetByID() returned unexpected user: %#v", got)
	}

	gotByLocal, err := store.GetByLocal(ctx, user.LocalPart)
	if err != nil {
		t.Fatalf("GetByLocal() failed: %v", err)
	}
	if gotByLocal.ID != user.ID {
		t.Fatalf("GetByLocal() returned unexpected user: %#v", gotByLocal)
	}

	all, err := store.GetAll(ctx, util.Filter{})
	if err != nil {
		t.Fatalf("GetAll() failed: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("GetAll() expected 1 user, got %d", len(all))
	}

	updated := user
	updated.Nome = "Alice Updated"
	updated.Foto = "https://example.com/alice-updated.png"

	if err := store.Update(ctx, &updated); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}

	gotUpdated, err := store.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID() after update failed: %v", err)
	}
	if gotUpdated.Nome != updated.Nome || gotUpdated.Foto != updated.Foto {
		t.Fatalf("Update() did not persist changes: %#v", gotUpdated)
	}

	deleted, err := store.Delete(ctx, user.ID)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	if deleted.ID != user.ID {
		t.Fatalf("Delete() returned unexpected user: %#v", deleted)
	}

	if _, err := store.GetByID(ctx, user.ID); !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}

func TestUsuarioStoreCreate_LocalpartAlreadyExists(t *testing.T) {
	resetTables(t)

	store := NewUsuarioStore(testDB)
	ctx := context.Background()

	user := model.Usuario{
		ID:          "@alice:example.com",
		LocalPart:   "alice",
		Nome:        "Alice",
		Senha:       "secret",
		Foto:        "https://example.com/alice.png",
		DataCriacao: baseTime,
	}

	if err := store.Create(ctx, &user); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	duplicate := model.Usuario{
		ID:          "@alice2:example.com",
		LocalPart:   "alice",
		Nome:        "Alice Two",
		Senha:       "secret2",
		Foto:        "https://example.com/alice2.png",
		DataCriacao: baseTime,
	}

	err := store.Create(ctx, &duplicate)
	if err == nil {
		t.Fatalf("expected error when localpart already exists")
	}
	if !errors.Is(err, types.ErrLocalpartInUse) {
		t.Fatalf("expected ErrLocalpartInUse, got: %v", err)
	}
}
