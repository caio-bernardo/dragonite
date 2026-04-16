package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/model"
	"github.com/caio-bernardo/dragonite/internal/types"
	"github.com/caio-bernardo/dragonite/internal/util"
)

func TestUsuarioCanalStoreCompositeQueriesAndUpdates(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@member:example.com",
		LocalPart:   "member",
		Nome:        "Member",
		Senha:       "password",
		Foto:        "https://example.com/member.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "General",
		Descricao:   "General discussion",
		Foto:        "https://example.com/room.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime.Add(2 * time.Hour),
	}
	insertCanal(t, canal)

	evento1 := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         user.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}
	insertEvento(t, evento1)

	evento2 := model.Evento{
		ID:               "$event-2:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         user.ID,
		Conteudo:         `{"membership":"leave"}`,
		OrigemServidorTS: 1234567891,
		StreamOrdering:   2,
	}
	insertEvento(t, evento2)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	uc := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  evento1.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}
	if got.CanalID != canal.ID || got.UsuarioID != user.ID || got.EventoID != evento1.ID || got.Membresia != "join" {
		t.Fatalf("GetByComposedID() returned unexpected record: %#v", got)
	}

	all, err := store.GetAll(ctx, util.Filter{})
	if err != nil {
		t.Fatalf("GetAll() failed: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("GetAll() expected 1 record, got %d", len(all))
	}

	byUser, err := store.GetAllByUsuarioID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetAllByUsuarioID() failed: %v", err)
	}
	if len(byUser) != 1 {
		t.Fatalf("GetAllByUsuarioID() expected 1 record, got %d", len(byUser))
	}

	byCanal, err := store.GetAllByCanalID(ctx, canal.ID)
	if err != nil {
		t.Fatalf("GetAllByCanalID() failed: %v", err)
	}
	if len(byCanal) != 1 {
		t.Fatalf("GetAllByCanalID() expected 1 record, got %d", len(byCanal))
	}

	updated := uc
	updated.EventoID = evento2.ID
	updated.Membresia = "leave"

	if err := store.Update(ctx, &updated); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}

	gotUpdated, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() after update failed: %v", err)
	}
	if gotUpdated.EventoID != evento2.ID || gotUpdated.Membresia != "leave" {
		t.Fatalf("Update() did not persist changes: %#v", gotUpdated)
	}

	deleted, err := store.Delete(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	if deleted.CanalID != canal.ID || deleted.UsuarioID != user.ID {
		t.Fatalf("Delete() returned unexpected record: %#v", deleted)
	}

	if _, err := store.GetByComposedID(ctx, user.ID, canal.ID); !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}
