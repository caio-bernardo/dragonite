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

func TestEventoStoreCRUDAndCleanup(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@event-sender:example.com",
		LocalPart:   "event-sender",
		Nome:        "Event Sender",
		Senha:       "password",
		Foto:        "https://example.com/sender.png",
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

	store := NewEventoStore(testDB)
	ctx := context.Background()

	evento := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"hello"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}

	if err := store.Create(ctx, &evento); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	got, err := store.GetByID(ctx, evento.ID)
	if err != nil {
		t.Fatalf("GetByID() failed: %v", err)
	}
	if got.ID != evento.ID || got.Tipo != evento.Tipo || got.CanalID != evento.CanalID || got.SenderID != evento.SenderID {
		t.Fatalf("GetByID() returned unexpected evento: %#v", got)
	}

	all, err := store.GetAll(ctx, util.Filter{})
	if err != nil {
		t.Fatalf("GetAll() failed: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("GetAll() expected 1 evento, got %d", len(all))
	}

	updated := evento
	updated.Tipo = "m.room.member"
	updated.StateKey = user.ID
	updated.Conteudo = `{"membership":"join"}`
	updated.StreamOrdering = 2

	if err := store.Update(ctx, &updated); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}

	gotUpdated, err := store.GetByID(ctx, evento.ID)
	if err != nil {
		t.Fatalf("GetByID() after update failed: %v", err)
	}
	if gotUpdated.Tipo != updated.Tipo || gotUpdated.StateKey != updated.StateKey || gotUpdated.StreamOrdering != updated.StreamOrdering {
		t.Fatalf("Update() did not persist changes: %#v", gotUpdated)
	}

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  evento.ID,
		Membresia: "join",
	})

	insertEstadoAtualCanal(t, canal.ID, "m.room.member", user.ID, evento.ID)

	deleted, err := store.Delete(ctx, evento.ID)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	if deleted.ID != evento.ID {
		t.Fatalf("Delete() returned unexpected evento: %#v", deleted)
	}

	if _, err := store.GetByID(ctx, evento.ID); !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}
