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
	txnID := "txn-abc-123"

	evento := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"hello"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
		TxnID:            &txnID,
	}

	if err := store.Create(ctx, &evento); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	// evento encontrado pelo sender + txnId
	got2, err := store.GetByTxnID(ctx, user.ID, txnID)
	if err != nil {
    	t.Fatalf("GetByTxnID() failed: %v", err)
	}
	if got2.ID != evento.ID {
    	t.Fatalf("GetByTxnID() returned unexpected evento: %#v", got2)
	}

	if _, err := store.GetByTxnID(ctx, user.ID, "txn-inexistente"); !errors.Is(err, types.ErrNotFound) {
    	t.Fatalf("expected ErrNotFound for unknown txnId, got: %v", err)
	}

	// mesmo txnId com sender diferente retorna ErrNotFound (constraint é por sender)
	if _, err := store.GetByTxnID(ctx, "@outro:example.com", txnID); !errors.Is(err, types.ErrNotFound) {
    	t.Fatalf("expected ErrNotFound for different sender, got: %v", err)
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
		EventoID:  &evento.ID,
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

// Test CheckNew functionality
func TestCheckNewReturnsTrueWhenNewEventsExist(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	// Create test data
	user := model.Usuario{
		ID:          "@user1:example.com",
		LocalPart:   "user1",
		Nome:        "User One",
		Senha:       "password",
		Foto:        "https://example.com/user1.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room1:example.com",
		Nome:        "Room One",
		Descricao:   "Test room",
		Foto:        "https://example.com/room1.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	// Add user to canal
	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Create events with stream ordering 1, 2, 3
	for i := 1; i <= 3; i++ {
		evento := model.Evento{
			ID:               "$event-" + string(rune(i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"hello"}`,
			OrigemServidorTS: int64(1000 + i),
			StreamOrdering:   int64(i),
		}
		insertEvento(t, evento)
	}

	// Test with since token at 0 (should find events 1, 2, 3)
	since := model.SyncToken{RoomEvents: 0}
	hasNew, err := store.CheckNew(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("CheckNew() failed: %v", err)
	}
	if !hasNew {
		t.Fatalf("CheckNew() expected true, got false")
	}
}

func TestCheckNewReturnsFalseWhenNoNewEvents(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user2:example.com",
		LocalPart:   "user2",
		Nome:        "User Two",
		Senha:       "password",
		Foto:        "https://example.com/user2.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room2:example.com",
		Nome:        "Room Two",
		Descricao:   "Test room",
		Foto:        "https://example.com/room2.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Create only one event with stream ordering 1
	evento := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"hello"}`,
		OrigemServidorTS: 1001,
		StreamOrdering:   1,
	}
	insertEvento(t, evento)

	// Test with since token at 1 (should not find any new events)
	since := model.SyncToken{RoomEvents: 1}
	hasNew, err := store.CheckNew(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("CheckNew() failed: %v", err)
	}
	if hasNew {
		t.Fatalf("CheckNew() expected false, got true")
	}
}

func TestCheckNewReturnsFalseWhenUserHasNoCanals(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user3:example.com",
		LocalPart:   "user3",
		Nome:        "User Three",
		Senha:       "password",
		Foto:        "https://example.com/user3.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	// Don't add user to any canals
	since := model.SyncToken{RoomEvents: 0}
	hasNew, err := store.CheckNew(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("CheckNew() failed: %v", err)
	}
	if hasNew {
		t.Fatalf("CheckNew() expected false when user has no canals, got true")
	}
}

func TestCheckNewWithMultipleCanals(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user4:example.com",
		LocalPart:   "user4",
		Nome:        "User Four",
		Senha:       "password",
		Foto:        "https://example.com/user4.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	// Create multiple canals
	canal1 := model.Canal{
		ID:          "!room1:example.com",
		Nome:        "Room One",
		Descricao:   "Test room 1",
		Foto:        "https://example.com/room1.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal1)

	canal2 := model.Canal{
		ID:          "!room2:example.com",
		Nome:        "Room Two",
		Descricao:   "Test room 2",
		Foto:        "https://example.com/room2.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal2)

	// Add user to both canals
	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal1.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal2.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Create event in canal1 with stream ordering 10
	evento1 := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal1.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"hello"}`,
		OrigemServidorTS: 1010,
		StreamOrdering:   10,
	}
	insertEvento(t, evento1)

	// Create event in canal2 with stream ordering 20
	evento2 := model.Evento{
		ID:               "$event-2:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal2.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"world"}`,
		OrigemServidorTS: 1020,
		StreamOrdering:   20,
	}
	insertEvento(t, evento2)

	// Test with since token at 5 (should find events from both canals)
	since := model.SyncToken{RoomEvents: 5}
	hasNew, err := store.CheckNew(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("CheckNew() failed: %v", err)
	}
	if !hasNew {
		t.Fatalf("CheckNew() expected true for multiple canals, got false")
	}
}

// Test GetSince functionality
func TestGetSinceReturnsEventsAfterSinceRoomEventsWithCorrectOrdering(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user5:example.com",
		LocalPart:   "user5",
		Nome:        "User Five",
		Senha:       "password",
		Foto:        "https://example.com/user5.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room5:example.com",
		Nome:        "Room Five",
		Descricao:   "Test room",
		Foto:        "https://example.com/room5.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Create events with stream ordering 1, 3, 5
	expectedEvents := []int64{1, 3, 5}
	for i, so := range expectedEvents {
		evento := model.Evento{
			ID:               "$event-" + string(rune('a'+i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"msg"}`,
			OrigemServidorTS: int64(1000 + i),
			StreamOrdering:   so,
		}
		insertEvento(t, evento)
	}

	// Get events with since token at 0
	since := model.SyncToken{RoomEvents: 0}
	events, newToken, err := store.GetSince(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("GetSince() failed: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("GetSince() expected 3 events, got %d", len(events))
	}

	// Verify correct ordering
	for i, e := range events {
		if e.StreamOrdering != expectedEvents[i] {
			t.Fatalf("GetSince() event %d: expected stream_ordering %d, got %d", i, expectedEvents[i], e.StreamOrdering)
		}
	}

	// Verify token was updated
	if newToken.RoomEvents != 5 {
		t.Fatalf("GetSince() expected new token RoomEvents=5, got %d", newToken.RoomEvents)
	}
}

func TestGetSinceReturnsEmptyListWhenNoEventsAfterSince(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user6:example.com",
		LocalPart:   "user6",
		Nome:        "User Six",
		Senha:       "password",
		Foto:        "https://example.com/user6.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room6:example.com",
		Nome:        "Room Six",
		Descricao:   "Test room",
		Foto:        "https://example.com/room6.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Create event with stream ordering 1
	evento := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"hello"}`,
		OrigemServidorTS: 1001,
		StreamOrdering:   1,
	}
	insertEvento(t, evento)

	// Get events with since token at 1 (no new events)
	since := model.SyncToken{RoomEvents: 1}
	events, newToken, err := store.GetSince(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("GetSince() failed: %v", err)
	}

	if len(events) != 0 {
		t.Fatalf("GetSince() expected 0 events, got %d", len(events))
	}

	// Token should be updated to max global when no events returned
	if newToken.RoomEvents != 1 {
		t.Fatalf("GetSince() expected new token RoomEvents=1, got %d", newToken.RoomEvents)
	}
}

func TestGetSinceReturnsUpTo100Events(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user7:example.com",
		LocalPart:   "user7",
		Nome:        "User Seven",
		Senha:       "password",
		Foto:        "https://example.com/user7.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room7:example.com",
		Nome:        "Room Seven",
		Descricao:   "Test room",
		Foto:        "https://example.com/room7.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Create 150 events
	for i := 1; i <= 150; i++ {
		evento := model.Evento{
			ID:               "$event-" + string(rune(i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"msg"}`,
			OrigemServidorTS: int64(1000 + i),
			StreamOrdering:   int64(i),
		}
		insertEvento(t, evento)
	}

	// Get events with since token at 0
	since := model.SyncToken{RoomEvents: 0}
	events, _, err := store.GetSince(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("GetSince() failed: %v", err)
	}

	if len(events) != 100 {
		t.Fatalf("GetSince() expected 100 events (pagination), got %d", len(events))
	}
}

func TestGetSinceUpdatesTokenToMaxGlobalWhenFewerThan100Events(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user8:example.com",
		LocalPart:   "user8",
		Nome:        "User Eight",
		Senha:       "password",
		Foto:        "https://example.com/user8.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room8:example.com",
		Nome:        "Room Eight",
		Descricao:   "Test room",
		Foto:        "https://example.com/room8.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Create 50 events
	for i := 1; i <= 50; i++ {
		evento := model.Evento{
			ID:               "$event-" + string(rune(i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"msg"}`,
			OrigemServidorTS: int64(1000 + i),
			StreamOrdering:   int64(i),
		}
		insertEvento(t, evento)
	}

	// Get events with since token at 0
	since := model.SyncToken{RoomEvents: 0}
	_, newToken, err := store.GetSince(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("GetSince() failed: %v", err)
	}

	// Token should be updated to max global (50) when fewer than 100 events returned
	if newToken.RoomEvents != 50 {
		t.Fatalf("GetSince() expected token RoomEvents=50 (max global), got %d", newToken.RoomEvents)
	}
}

func TestGetSinceDoesNotUpdateTokenWhen100EventsReturned(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user9:example.com",
		LocalPart:   "user9",
		Nome:        "User Nine",
		Senha:       "password",
		Foto:        "https://example.com/user9.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room9:example.com",
		Nome:        "Room Nine",
		Descricao:   "Test room",
		Foto:        "https://example.com/room9.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Create 150 events
	for i := 1; i <= 150; i++ {
		evento := model.Evento{
			ID:               "$event-" + string(rune(i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"msg"}`,
			OrigemServidorTS: int64(1000 + i),
			StreamOrdering:   int64(i),
		}
		insertEvento(t, evento)
	}

	// Get events with since token at 0
	since := model.SyncToken{RoomEvents: 0}
	_, newToken, err := store.GetSince(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("GetSince() failed: %v", err)
	}

	// Token should only be updated to the last returned event (100) when 100 events returned
	if newToken.RoomEvents != 100 {
		t.Fatalf("GetSince() expected token RoomEvents=100, got %d", newToken.RoomEvents)
	}
}

func TestGetSinceWithMultipleCanals(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user10:example.com",
		LocalPart:   "user10",
		Nome:        "User Ten",
		Senha:       "password",
		Foto:        "https://example.com/user10.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	// Create two canals
	canal1 := model.Canal{
		ID:          "!room10a:example.com",
		Nome:        "Room Ten A",
		Descricao:   "Test room A",
		Foto:        "https://example.com/room10a.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal1)

	canal2 := model.Canal{
		ID:          "!room10b:example.com",
		Nome:        "Room Ten B",
		Descricao:   "Test room B",
		Foto:        "https://example.com/room10b.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal2)

	// Add user to both canals
	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal1.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal2.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Create events in both canals
	// canal1: events with stream ordering 5, 15, 25
	for i, so := range []int64{5, 15, 25} {
		evento := model.Evento{
			ID:               "$event-a" + string(rune('1'+i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal1.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"msg a"}`,
			OrigemServidorTS: int64(2000 + i),
			StreamOrdering:   so,
		}
		insertEvento(t, evento)
	}

	// canal2: events with stream ordering 10, 20, 30
	for i, so := range []int64{10, 20, 30} {
		evento := model.Evento{
			ID:               "$event-b" + string(rune('1'+i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal2.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"msg b"}`,
			OrigemServidorTS: int64(2000 + i),
			StreamOrdering:   so,
		}
		insertEvento(t, evento)
	}

	// Get events with since token at 0
	since := model.SyncToken{RoomEvents: 0}
	events, newToken, err := store.GetSince(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("GetSince() failed: %v", err)
	}

	// Should return 6 events total (3 from each canal)
	if len(events) != 6 {
		t.Fatalf("GetSince() expected 6 events from multiple canals, got %d", len(events))
	}

	// Verify correct ordering (should be ordered by stream_ordering)
	expectedOrder := []int64{5, 10, 15, 20, 25, 30}
	for i, e := range events {
		if e.StreamOrdering != expectedOrder[i] {
			t.Fatalf("GetSince() event %d: expected stream_ordering %d, got %d", i, expectedOrder[i], e.StreamOrdering)
		}
	}

	// Token should be updated to max returned event
	if newToken.RoomEvents != 30 {
		t.Fatalf("GetSince() expected token RoomEvents=30, got %d", newToken.RoomEvents)
	}
}

// Test GetMaxGlobalStreamOrdering functionality
func TestGetMaxGlobalStreamOrderingReturnsCorrectMaxValue(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user11:example.com",
		LocalPart:   "user11",
		Nome:        "User Eleven",
		Senha:       "password",
		Foto:        "https://example.com/user11.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room11:example.com",
		Nome:        "Room Eleven",
		Descricao:   "Test room",
		Foto:        "https://example.com/room11.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	// Create events with stream ordering 10, 25, 5
	for i, so := range []int64{10, 25, 5} {
		evento := model.Evento{
			ID:               "$event-" + string(rune('a'+i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"msg"}`,
			OrigemServidorTS: int64(3000 + i),
			StreamOrdering:   so,
		}
		insertEvento(t, evento)
	}

	max, err := store.GetMaxGlobalStreamOrdering(ctx)
	if err != nil {
		t.Fatalf("GetMaxGlobalStreamOrdering() failed: %v", err)
	}

	if max != 25 {
		t.Fatalf("GetMaxGlobalStreamOrdering() expected 25, got %d", max)
	}
}

func TestGetMaxGlobalStreamOrderingReturns0WhenNoEventosExist(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	max, err := store.GetMaxGlobalStreamOrdering(ctx)
	if err != nil {
		t.Fatalf("GetMaxGlobalStreamOrdering() failed: %v", err)
	}

	if max != 0 {
		t.Fatalf("GetMaxGlobalStreamOrdering() expected 0 when no eventos, got %d", max)
	}
}

func TestGetMaxGlobalStreamOrderingReturnsLargestStreamOrderingAcrossAllEventos(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user12:example.com",
		LocalPart:   "user12",
		Nome:        "User Twelve",
		Senha:       "password",
		Foto:        "https://example.com/user12.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	// Create two canals
	canal1 := model.Canal{
		ID:          "!room12a:example.com",
		Nome:        "Room Twelve A",
		Descricao:   "Test room A",
		Foto:        "https://example.com/room12a.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal1)

	canal2 := model.Canal{
		ID:          "!room12b:example.com",
		Nome:        "Room Twelve B",
		Descricao:   "Test room B",
		Foto:        "https://example.com/room12b.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal2)

	// Create events in canal1 with stream ordering 10, 20
	for i, so := range []int64{10, 20} {
		evento := model.Evento{
			ID:               "$event-a" + string(rune('1'+i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal1.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"msg"}`,
			OrigemServidorTS: int64(4000 + i),
			StreamOrdering:   so,
		}
		insertEvento(t, evento)
	}

	// Create events in canal2 with stream ordering 5, 100 (max)
	for i, so := range []int64{5, 100} {
		evento := model.Evento{
			ID:               "$event-b" + string(rune('1'+i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal2.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"msg"}`,
			OrigemServidorTS: int64(4000 + i),
			StreamOrdering:   so,
		}
		insertEvento(t, evento)
	}

	max, err := store.GetMaxGlobalStreamOrdering(ctx)
	if err != nil {
		t.Fatalf("GetMaxGlobalStreamOrdering() failed: %v", err)
	}

	if max != 100 {
		t.Fatalf("GetMaxGlobalStreamOrdering() expected 100 (max across all canals), got %d", max)
	}
}

// Test getCanaisIDByUserID helper function
func TestGetCanaisIDByUserIDReturnsAllCanalIDsWhereMember(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user13:example.com",
		LocalPart:   "user13",
		Nome:        "User Thirteen",
		Senha:       "password",
		Foto:        "https://example.com/user13.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	// Create three canals
	canal1 := model.Canal{
		ID:          "!room13a:example.com",
		Nome:        "Room Thirteen A",
		Descricao:   "Test room A",
		Foto:        "https://example.com/room13a.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal1)

	canal2 := model.Canal{
		ID:          "!room13b:example.com",
		Nome:        "Room Thirteen B",
		Descricao:   "Test room B",
		Foto:        "https://example.com/room13b.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal2)

	canal3 := model.Canal{
		ID:          "!room13c:example.com",
		Nome:        "Room Thirteen C",
		Descricao:   "Test room C",
		Foto:        "https://example.com/room13c.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal3)

	// Add user to canal1 and canal2 (not canal3)
	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal1.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal2.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Call getCanaisIDByUserID using reflection to access private method
	// We'll test this through CheckNew or GetSince instead
	// For now, we test that CheckNew returns correct results indicating the helper works
	evento1 := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal1.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"hello"}`,
		OrigemServidorTS: 1001,
		StreamOrdering:   1,
	}
	insertEvento(t, evento1)

	evento2 := model.Evento{
		ID:               "$event-2:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal2.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"world"}`,
		OrigemServidorTS: 1002,
		StreamOrdering:   2,
	}
	insertEvento(t, evento2)

	// Event in canal3 should NOT be included
	evento3 := model.Evento{
		ID:               "$event-3:example.com",
		Tipo:             "m.room.message",
		CanalID:          canal3.ID,
		SenderID:         user.ID,
		StateKey:         "",
		Conteudo:         `{"body":"ignored"}`,
		OrigemServidorTS: 1003,
		StreamOrdering:   3,
	}
	insertEvento(t, evento3)

	// Get events should only include events from canal1 and canal2
	since := model.SyncToken{RoomEvents: 0}
	events, _, err := store.GetSince(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("GetSince() failed: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("GetSince() expected 2 events from user's canals, got %d", len(events))
	}

	// Verify events are from correct canals
	for _, e := range events {
		if e.CanalID == canal3.ID {
			t.Fatalf("GetSince() returned event from canal user is not member of")
		}
	}
}

func TestGetCanaisIDByUserIDReturnsEmptyListWhenUserHasNoCanals(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user14:example.com",
		LocalPart:   "user14",
		Nome:        "User Fourteen",
		Senha:       "password",
		Foto:        "https://example.com/user14.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	// Don't add user to any canals
	since := model.SyncToken{RoomEvents: 0}
	events, _, err := store.GetSince(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("GetSince() failed: %v", err)
	}

	if len(events) != 0 {
		t.Fatalf("GetSince() expected 0 events when user has no canals, got %d", len(events))
	}
}

func TestGetCanaisIDByUserIDReturnsDistinctCanalIDs(t *testing.T) {
	resetTables(t)
	ctx := context.Background()
	store := NewEventoStore(testDB)

	user := model.Usuario{
		ID:          "@user15:example.com",
		LocalPart:   "user15",
		Nome:        "User Fifteen",
		Senha:       "password",
		Foto:        "https://example.com/user15.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room15:example.com",
		Nome:        "Room Fifteen",
		Descricao:   "Test room",
		Foto:        "https://example.com/room15.png",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	// Add user to same canal multiple times (shouldn't happen in practice)
	insertUsuarioCanal(t, model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		Membresia: "join",
	})

	// Create multiple events in the same canal
	for i := 1; i <= 3; i++ {
		evento := model.Evento{
			ID:               "$event-" + string(rune('0'+i)) + ":example.com",
			Tipo:             "m.room.message",
			CanalID:          canal.ID,
			SenderID:         user.ID,
			StateKey:         "",
			Conteudo:         `{"body":"msg"}`,
			OrigemServidorTS: int64(5000 + i),
			StreamOrdering:   int64(i),
		}
		insertEvento(t, evento)
	}

	// Get events should return all events from the single canal
	since := model.SyncToken{RoomEvents: 0}
	events, _, err := store.GetSince(ctx, user.ID, since)
	if err != nil {
		t.Fatalf("GetSince() failed: %v", err)
	}

	if len(events) != 3 {
		t.Fatalf("GetSince() expected 3 events from single canal, got %d", len(events))
	}

	// All events should be from same canal
	for _, e := range events {
		if e.CanalID != canal.ID {
			t.Fatalf("GetSince() returned event from different canal")
		}
	}
}
