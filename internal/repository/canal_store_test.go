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

func TestCanalStoreCRUDAndCleanup(t *testing.T) {
	resetTables(t)

	owner := model.Usuario{
		ID:          "@channel-owner:example.com",
		LocalPart:   "channel-owner",
		Nome:        "Channel Owner",
		Senha:       "password",
		Foto:        "https://example.com/channel-owner.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, owner)

	store := NewChannelStore(testDB)
	ctx := context.Background()

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "General",
		Descricao:   "General discussion",
		Foto:        "https://example.com/room.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   owner.ID,
		DataCriacao: baseTime.Add(2 * time.Hour),
	}

	if err := store.Create(ctx, &canal); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	got, err := store.GetByID(ctx, canal.ID)
	if err != nil {
		t.Fatalf("GetByID() failed: %v", err)
	}
	if got.ID != canal.ID || got.Nome != canal.Nome || got.IsPublic != canal.IsPublic || got.CriadorID != canal.CriadorID {
		t.Fatalf("GetByID() returned unexpected canal: %#v", got)
	}

	all, err := store.GetAll(ctx, util.Filter{})
	if err != nil {
		t.Fatalf("GetAll() failed: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("GetAll() expected 1 canal, got %d", len(all))
	}

	updated := canal
	updated.Nome = "General Updated"
	updated.Descricao = "Updated description"
	updated.IsPublic = false
	updated.Foto = "https://example.com/room-updated.png"

	if err := store.Update(ctx, &updated); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}

	gotUpdated, err := store.GetByID(ctx, canal.ID)
	if err != nil {
		t.Fatalf("GetByID() after update failed: %v", err)
	}
	if gotUpdated.Nome != updated.Nome || gotUpdated.Descricao != updated.Descricao || gotUpdated.IsPublic != updated.IsPublic {
		t.Fatalf("Update() did not persist changes: %#v", gotUpdated)
	}

	evento := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal.ID,
		SenderID:         owner.ID,
		StateKey:         "",
		Conteudo:         `{"body":"hello"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}
	insertEvento(t, evento)

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: owner.ID,
		EventoID:  evento.ID,
		Membresia: "join",
	})

	insertEstadoAtualCanal(t, canal.ID, "m.room.member", owner.ID, evento.ID)

	deleted, err := store.Delete(ctx, canal.ID)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	if deleted.ID != canal.ID {
		t.Fatalf("Delete() returned unexpected canal: %#v", deleted)
	}

	if _, err := store.GetByID(ctx, canal.ID); !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}
