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

func TestArestaEventoStoreCRUDAndQueries(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@aresta-user:example.com",
		LocalPart:   "aresta-user",
		Nome:        "Aresta User",
		Senha:       "password",
		Foto:        "https://example.com/aresta-user.png",
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

	eventoAntecessor := model.Evento{
		ID:               "$event-antecessor:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"prev"}`,
		OrigemServidorTS: 1234567888,
		StreamOrdering:   1,
	}
	insertEvento(t, eventoAntecessor)

	eventoAtual := model.Evento{
		ID:               "$event-atual:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"current"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   2,
	}
	insertEvento(t, eventoAtual)

	store := NewArestaEventoStore(testDB)
	ctx := context.Background()

	aresta := model.ArestaEvento{
		EventoID:           eventoAtual.ID,
		EventoAntecessorID: eventoAntecessor.ID,
		CanalID:            canal.ID,
		IsState:            false,
	}

	if err := store.Create(ctx, &aresta); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, eventoAtual.ID, eventoAntecessor.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}
	if got.EventoID != aresta.EventoID || got.EventoAntecessorID != aresta.EventoAntecessorID || got.CanalID != aresta.CanalID || got.IsState != aresta.IsState {
		t.Fatalf("GetByComposedID() returned unexpected record: %#v", got)
	}

	all, err := store.GetAll(ctx, util.Filter{})
	if err != nil {
		t.Fatalf("GetAll() failed: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("GetAll() expected 1 record, got %d", len(all))
	}

	byEvento, err := store.GetAllByEventoID(ctx, eventoAtual.ID)
	if err != nil {
		t.Fatalf("GetAllByEventoID() failed: %v", err)
	}
	if len(byEvento) != 1 {
		t.Fatalf("GetAllByEventoID() expected 1 record, got %d", len(byEvento))
	}

	byCanal, err := store.GetAllByCanalID(ctx, canal.ID)
	if err != nil {
		t.Fatalf("GetAllByCanalID() failed: %v", err)
	}
	if len(byCanal) != 1 {
		t.Fatalf("GetAllByCanalID() expected 1 record, got %d", len(byCanal))
	}

	updated := aresta
	updated.IsState = true

	if err := store.Update(ctx, &updated); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}

	gotUpdated, err := store.GetByComposedID(ctx, eventoAtual.ID, eventoAntecessor.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() after update failed: %v", err)
	}
	if gotUpdated.IsState != updated.IsState {
		t.Fatalf("Update() did not persist changes: %#v", gotUpdated)
	}

	deleted, err := store.Delete(ctx, eventoAtual.ID, eventoAntecessor.ID)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	if deleted.EventoID != aresta.EventoID || deleted.EventoAntecessorID != aresta.EventoAntecessorID {
		t.Fatalf("Delete() returned unexpected record: %#v", deleted)
	}

	if _, err := store.GetByComposedID(ctx, eventoAtual.ID, eventoAntecessor.ID); !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}
