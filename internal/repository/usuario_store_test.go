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

func TestUsuarioStore_GetByID_NotFound(t *testing.T) {
	resetTables(t)
	store := NewUsuarioStore(testDB)

	_, err := store.GetByID(context.Background(), "@naoexiste:example.com")
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestUsuarioStore_GetByLocal_NotFound(t *testing.T) {
	resetTables(t)
	store := NewUsuarioStore(testDB)

	_, err := store.GetByLocal(context.Background(), "naoexiste")
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestUsuarioStore_Update_NotFound(t *testing.T) {
	resetTables(t)
	store := NewUsuarioStore(testDB)

	err := store.Update(context.Background(), &model.Usuario{
		ID:          "@naoexiste:example.com",
		LocalPart:   "naoexiste",
		Nome:        "Ghost",
		DataCriacao: baseTime,
	})
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestUsuarioStore_Delete_NotFound(t *testing.T) {
	resetTables(t)
	store := NewUsuarioStore(testDB)

	_, err := store.Delete(context.Background(), "@naoexiste:example.com")
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestUsuarioStore_Search(t *testing.T) {
	resetTables(t)
	store := NewUsuarioStore(testDB)
	ctx := context.Background()

	users := []model.Usuario{
		{ID: "@alice:example.com", LocalPart: "alice", Nome: "Alice Wonder", Senha: "s", DataCriacao: baseTime},
		{ID: "@bob:example.com", LocalPart: "bob", Nome: "Bob Builder", Senha: "s", DataCriacao: baseTime},
		{ID: "@charlie:example.com", LocalPart: "charlie", Nome: "Charlie Chaplin", Senha: "s", DataCriacao: baseTime},
	}
	for _, u := range users {
		u := u
		if err := store.Create(ctx, &u); err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
	}

	// Busca por nome parcial
	results, err := store.Search(ctx, "alice", 10)
	if err != nil {
		t.Fatalf("Search() failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ID != "@alice:example.com" {
		t.Errorf("expected alice, got %s", results[0].ID)
	}

	// Busca por localpart via user_id
	results, err = store.Search(ctx, "bob", 10)
	if err != nil {
		t.Fatalf("Search() failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Busca sem resultado
	results, err = store.Search(ctx, "xyz_naoexiste", 10)
	if err != nil {
		t.Fatalf("Search() failed: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}

	// Respeita limit
	results, err = store.Search(ctx, "example", 2)
	if err != nil {
		t.Fatalf("Search() failed: %v", err)
	}
	if len(results) > 2 {
		t.Fatalf("expected at most 2 results, got %d", len(results))
	}
}

func TestUsuarioStore_GetNameAndPhotoByID(t *testing.T) {
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

	got, err := store.GetNameAndPhotoByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetNameAndPhotoByID() failed: %v", err)
	}
	if got.Nome != user.Nome {
		t.Errorf("expected nome %q, got %q", user.Nome, got.Nome)
	}
	if got.Foto != user.Foto {
		t.Errorf("expected foto %q, got %q", user.Foto, got.Foto)
	}

	// Usuário sem foto
	userSemFoto := model.Usuario{
		ID:          "@bob:example.com",
		LocalPart:   "bob",
		Nome:        "Bob",
		Senha:       "secret",
		DataCriacao: baseTime,
	}
	if err := store.Create(ctx, &userSemFoto); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}
	got, err = store.GetNameAndPhotoByID(ctx, userSemFoto.ID)
	if err != nil {
		t.Fatalf("GetNameAndPhotoByID() sem foto failed: %v", err)
	}
	if got.Foto != "" {
		t.Errorf("expected empty foto, got %q", got.Foto)
	}

	// Não encontrado
	_, err = store.GetNameAndPhotoByID(ctx, "@naoexiste:example.com")
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestUsuarioStore_UpdateProfileKey(t *testing.T) {
	resetTables(t)
	store := NewUsuarioStore(testDB)
	ctx := context.Background()

	user := model.Usuario{
		ID:          "@alice:example.com",
		LocalPart:   "alice",
		Nome:        "Alice",
		Senha:       "secret",
		DataCriacao: baseTime,
	}
	if err := store.Create(ctx, &user); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	// Atualiza nome
	if err := store.UpdateProfileKey(ctx, user.ID, "nome_usuario", "Alice Nova"); err != nil {
		t.Fatalf("UpdateProfileKey() failed: %v", err)
	}
	got, _ := store.GetByID(ctx, user.ID)
	if got.Nome != "Alice Nova" {
		t.Errorf("expected nome 'Alice Nova', got %q", got.Nome)
	}

	// Atualiza foto
	if err := store.UpdateProfileKey(ctx, user.ID, "foto_usuario", "https://example.com/new.png"); err != nil {
		t.Fatalf("UpdateProfileKey() foto failed: %v", err)
	}
	got, _ = store.GetByID(ctx, user.ID)
	if got.Foto != "https://example.com/new.png" {
		t.Errorf("expected foto atualizada, got %q", got.Foto)
	}

	// Usuário não encontrado
	err := store.UpdateProfileKey(ctx, "@naoexiste:example.com", "nome_usuario", "Ghost")
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestUsuarioStore_ClearProfileKey(t *testing.T) {
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

	// Limpa foto
	if err := store.ClearProfileKey(ctx, user.ID, "foto_usuario"); err != nil {
		t.Fatalf("ClearProfileKey() failed: %v", err)
	}
	got, _ := store.GetByID(ctx, user.ID)
	if got.Foto != "" {
		t.Errorf("expected foto cleared, got %q", got.Foto)
	}

	// Usuário não encontrado
	err := store.ClearProfileKey(ctx, "@naoexiste:example.com", "foto_usuario")
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}