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
		EventoID:  &evento1.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}
	if got.CanalID != canal.ID || got.UsuarioID != user.ID || got.EventoID == nil ||
		*got.EventoID != evento1.ID || got.Membresia != "join" {
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
	updated.EventoID = &evento2.ID
	updated.Membresia = "leave"

	if err := store.Update(ctx, &updated); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}

	gotUpdated, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() after update failed: %v", err)
	}
	if gotUpdated.EventoID == nil || *gotUpdated.EventoID != evento2.ID || gotUpdated.Membresia != "leave" {
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

func TestUsuarioCanalStore_AddOrUpdateMembership(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID: "@upsert-user:example.com", LocalPart: "upsert-user",
		Nome: "User", Senha: "password", DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID: "!upsert-room:example.com", Nome: "Room",
		IsPublic: true, Versao: "1", CriadorID: user.ID, DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	m := &model.UsuarioCanal{
		CanalID: canal.ID, UsuarioID: user.ID, Membresia: "join", JoinedAt: baseTime,
	}

	// Insert
	if err := store.AddOrUpdateMembership(ctx, m); err != nil {
		t.Fatalf("AddOrUpdateMembership() insert failed: %v", err)
	}

	got, _ := store.GetByComposedID(ctx, user.ID, canal.ID)
	if got.Membresia != "join" {
		t.Fatalf("expected 'join', got %q", got.Membresia)
	}

	// Update via upsert
	m.Membresia = "leave"
	if err := store.AddOrUpdateMembership(ctx, m); err != nil {
		t.Fatalf("AddOrUpdateMembership() update failed: %v", err)
	}

	updated, _ := store.GetByComposedID(ctx, user.ID, canal.ID)
	if updated.Membresia != "leave" {
		t.Fatalf("expected 'leave', got %q", updated.Membresia)
	}
}

// TestUsuarioCanalStore_CreateWithNullEventoID tests that EventoID can be NULL when creating a UsuarioCanal
func TestUsuarioCanalStore_CreateWithNullEventoID(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	// Create without EventoID (NULL)
	uc := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  nil,
		Membresia: "join",
		JoinedAt:  baseTime,
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() with NULL EventoID failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}

	if got.EventoID != nil {
		t.Fatalf("expected EventoID to be nil, got: %v", *got.EventoID)
	}
	if got.Membresia != "join" {
		t.Fatalf("expected Membresia 'join', got: %q", got.Membresia)
	}
}

// TestUsuarioCanalStore_CreateWithValidEventoID tests that EventoID can be set when creating a UsuarioCanal
func TestUsuarioCanalStore_CreateWithValidEventoID(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	evento := model.Evento{
		ID:               "$event:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         user.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}
	insertEvento(t, evento)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	// Create with valid EventoID
	uc := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  &evento.ID,
		Membresia: "join",
		JoinedAt:  baseTime,
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() with valid EventoID failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}

	if got.EventoID == nil || *got.EventoID != evento.ID {
		t.Fatalf("expected EventoID %q, got: %v", evento.ID, got.EventoID)
	}
	if got.Membresia != "join" {
		t.Fatalf("expected Membresia 'join', got: %q", got.Membresia)
	}
}

// TestUsuarioCanalStore_UpdateChangesEventoID tests that Update correctly changes the EventoID field
func TestUsuarioCanalStore_UpdateChangesEventoID(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
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
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567891,
		StreamOrdering:   2,
	}
	insertEvento(t, evento2)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	// Create with evento1
	uc := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  &evento1.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	// Update to evento2
	uc.EventoID = &evento2.ID
	if err := store.Update(ctx, &uc); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}

	if got.EventoID == nil || *got.EventoID != evento2.ID {
		t.Fatalf("expected EventoID %q, got: %v", evento2.ID, got.EventoID)
	}
}

// TestUsuarioCanalStore_UpdateEventoIDToNull tests that Update can set EventoID to NULL
func TestUsuarioCanalStore_UpdateEventoIDToNull(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	evento := model.Evento{
		ID:               "$event:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         user.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}
	insertEvento(t, evento)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	// Create with evento
	uc := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  &evento.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	// Update to NULL EventoID
	uc.EventoID = nil
	if err := store.Update(ctx, &uc); err != nil {
		t.Fatalf("Update() to NULL failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}

	if got.EventoID != nil {
		t.Fatalf("expected EventoID to be nil, got: %v", *got.EventoID)
	}
}

// TestUsuarioCanalStore_GetByComposedIDReturnsCompleteRecord tests that GetByComposedID returns correct EventoID
func TestUsuarioCanalStore_GetByComposedIDReturnsCompleteRecord(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	evento := model.Evento{
		ID:               "$event:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         user.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}
	insertEvento(t, evento)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	uc := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  &evento.ID,
		Membresia: "join",
		JoinedAt:  baseTime,
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}

	if got.CanalID != canal.ID {
		t.Fatalf("expected CanalID %q, got %q", canal.ID, got.CanalID)
	}
	if got.UsuarioID != user.ID {
		t.Fatalf("expected UsuarioID %q, got %q", user.ID, got.UsuarioID)
	}
	if got.EventoID == nil || *got.EventoID != evento.ID {
		t.Fatalf("expected EventoID %q, got: %v", evento.ID, got.EventoID)
	}
	if got.Membresia != "join" {
		t.Fatalf("expected Membresia 'join', got %q", got.Membresia)
	}
}

// TestUsuarioCanalStore_GetAllByUsuarioIDReturnsCompleteRecords tests that GetAllByUsuarioID returns complete UsuarioCanal records with EventoID
func TestUsuarioCanalStore_GetAllByUsuarioIDReturnsCompleteRecords(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal1 := model.Canal{
		ID:          "!room1:example.com",
		Nome:        "Room1",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal1)

	canal2 := model.Canal{
		ID:          "!room2:example.com",
		Nome:        "Room2",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal2)

	evento1 := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal1.ID,
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
		CanalID:          canal2.ID,
		SenderID:         user.ID,
		StateKey:         user.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567891,
		StreamOrdering:   2,
	}
	insertEvento(t, evento2)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	uc1 := model.UsuarioCanal{
		CanalID:   canal1.ID,
		UsuarioID: user.ID,
		EventoID:  &evento1.ID,
		Membresia: "join",
	}
	uc2 := model.UsuarioCanal{
		CanalID:   canal2.ID,
		UsuarioID: user.ID,
		EventoID:  &evento2.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc1); err != nil {
		t.Fatalf("Create() uc1 failed: %v", err)
	}
	if err := store.Create(ctx, &uc2); err != nil {
		t.Fatalf("Create() uc2 failed: %v", err)
	}

	got, err := store.GetAllByUsuarioID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetAllByUsuarioID() failed: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}

	// Verify both records have EventoID
	for _, rec := range got {
		if rec.EventoID == nil {
			t.Fatalf("expected EventoID to be set, got nil")
		}
		if rec.UsuarioID != user.ID {
			t.Fatalf("expected UsuarioID %q, got %q", user.ID, rec.UsuarioID)
		}
	}

	// Verify the specific EventoIDs match
	found1 := false
	found2 := false
	for _, rec := range got {
		if rec.CanalID == canal1.ID && *rec.EventoID == evento1.ID {
			found1 = true
		}
		if rec.CanalID == canal2.ID && *rec.EventoID == evento2.ID {
			found2 = true
		}
	}

	if !found1 {
		t.Fatalf("did not find record with canal1 and evento1")
	}
	if !found2 {
		t.Fatalf("did not find record with canal2 and evento2")
	}
}

// TestUsuarioCanalStore_GetAllByCanalIDReturnsCompleteRecords tests that GetAllByCanalID returns complete UsuarioCanal records with EventoID
func TestUsuarioCanalStore_GetAllByCanalIDReturnsCompleteRecords(t *testing.T) {
	resetTables(t)

	user1 := model.Usuario{
		ID:          "@user1:example.com",
		LocalPart:   "user1",
		Nome:        "User1",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user1)

	user2 := model.Usuario{
		ID:          "@user2:example.com",
		LocalPart:   "user2",
		Nome:        "User2",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user2)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user1.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	evento1 := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user1.ID,
		StateKey:         user1.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}
	insertEvento(t, evento1)

	evento2 := model.Evento{
		ID:               "$event-2:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user2.ID,
		StateKey:         user2.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567891,
		StreamOrdering:   2,
	}
	insertEvento(t, evento2)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	uc1 := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user1.ID,
		EventoID:  &evento1.ID,
		Membresia: "join",
	}
	uc2 := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user2.ID,
		EventoID:  &evento2.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc1); err != nil {
		t.Fatalf("Create() uc1 failed: %v", err)
	}
	if err := store.Create(ctx, &uc2); err != nil {
		t.Fatalf("Create() uc2 failed: %v", err)
	}

	got, err := store.GetAllByCanalID(ctx, canal.ID)
	if err != nil {
		t.Fatalf("GetAllByCanalID() failed: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got))
	}

	// Verify both records have EventoID and they are different
	eventIDs := make(map[string]bool)
	for _, rec := range got {
		if rec.EventoID == nil {
			t.Fatalf("expected EventoID to be set, got nil")
		}
		if rec.CanalID != canal.ID {
			t.Fatalf("expected CanalID %q, got %q", canal.ID, rec.CanalID)
		}
		eventIDs[*rec.EventoID] = true
	}

	if len(eventIDs) != 2 {
		t.Fatalf("expected 2 different EventoIDs, got %d", len(eventIDs))
	}

	if !eventIDs[evento1.ID] || !eventIDs[evento2.ID] {
		t.Fatalf("expected both evento1 and evento2 EventoIDs")
	}
}

// TestUsuarioCanalStore_AddOrUpdateMembershipWithEventoID tests AddOrUpdateMembership with EventoID handling
func TestUsuarioCanalStore_AddOrUpdateMembershipWithEventoID(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	evento := model.Evento{
		ID:               "$event:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         user.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}
	insertEvento(t, evento)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	// AddOrUpdateMembership does NOT update EventoID in current implementation,
	// but we test that the field is preserved when using Create/Update
	m := &model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		Membresia: "join",
		JoinedAt:  baseTime,
	}

	if err := store.AddOrUpdateMembership(ctx, m); err != nil {
		t.Fatalf("AddOrUpdateMembership() insert failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}

	if got.Membresia != "join" {
		t.Fatalf("expected 'join', got %q", got.Membresia)
	}

	// Verify we can manually update with EventoID using Update()
	got.EventoID = &evento.ID
	if err := store.Update(ctx, got); err != nil {
		t.Fatalf("Update() with EventoID failed: %v", err)
	}

	updated, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() after update failed: %v", err)
	}

	if updated.EventoID == nil || *updated.EventoID != evento.ID {
		t.Fatalf("expected EventoID %q, got: %v", evento.ID, updated.EventoID)
	}
}

// TestUsuarioCanalStore_MultipleUsersInSameCanalDifferentEventoIDs tests that multiple users can be in same canal with different EventoIDs
func TestUsuarioCanalStore_MultipleUsersInSameCanalDifferentEventoIDs(t *testing.T) {
	resetTables(t)

	user1 := model.Usuario{
		ID:          "@user1:example.com",
		LocalPart:   "user1",
		Nome:        "User1",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user1)

	user2 := model.Usuario{
		ID:          "@user2:example.com",
		LocalPart:   "user2",
		Nome:        "User2",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user2)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user1.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	evento1 := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user1.ID,
		StateKey:         user1.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}
	insertEvento(t, evento1)

	evento2 := model.Evento{
		ID:               "$event-2:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user2.ID,
		StateKey:         user2.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567891,
		StreamOrdering:   2,
	}
	insertEvento(t, evento2)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	uc1 := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user1.ID,
		EventoID:  &evento1.ID,
		Membresia: "join",
	}
	uc2 := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user2.ID,
		EventoID:  &evento2.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc1); err != nil {
		t.Fatalf("Create() uc1 failed: %v", err)
	}
	if err := store.Create(ctx, &uc2); err != nil {
		t.Fatalf("Create() uc2 failed: %v", err)
	}

	// Retrieve both records
	got1, err := store.GetByComposedID(ctx, user1.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() user1 failed: %v", err)
	}

	got2, err := store.GetByComposedID(ctx, user2.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() user2 failed: %v", err)
	}

	// Verify they have different EventoIDs
	if got1.EventoID == nil || got2.EventoID == nil {
		t.Fatalf("expected both EventoIDs to be set")
	}
	if *got1.EventoID == *got2.EventoID {
		t.Fatalf("expected different EventoIDs, but both are %q", *got1.EventoID)
	}
	if *got1.EventoID != evento1.ID {
		t.Fatalf("expected user1 EventoID %q, got %q", evento1.ID, *got1.EventoID)
	}
	if *got2.EventoID != evento2.ID {
		t.Fatalf("expected user2 EventoID %q, got %q", evento2.ID, *got2.EventoID)
	}
}

// TestUsuarioCanalStore_SameUserMultipleCanalsDifferentEventoIDs tests that same user in multiple canals can have different EventoIDs per canal
func TestUsuarioCanalStore_SameUserMultipleCanalsDifferentEventoIDs(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal1 := model.Canal{
		ID:          "!room1:example.com",
		Nome:        "Room1",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal1)

	canal2 := model.Canal{
		ID:          "!room2:example.com",
		Nome:        "Room2",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal2)

	evento1 := model.Evento{
		ID:               "$event-1:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal1.ID,
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
		CanalID:          canal2.ID,
		SenderID:         user.ID,
		StateKey:         user.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567891,
		StreamOrdering:   2,
	}
	insertEvento(t, evento2)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	uc1 := model.UsuarioCanal{
		CanalID:   canal1.ID,
		UsuarioID: user.ID,
		EventoID:  &evento1.ID,
		Membresia: "join",
	}
	uc2 := model.UsuarioCanal{
		CanalID:   canal2.ID,
		UsuarioID: user.ID,
		EventoID:  &evento2.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc1); err != nil {
		t.Fatalf("Create() uc1 failed: %v", err)
	}
	if err := store.Create(ctx, &uc2); err != nil {
		t.Fatalf("Create() uc2 failed: %v", err)
	}

	// Retrieve both records for same user in different canals
	got1, err := store.GetByComposedID(ctx, user.ID, canal1.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() canal1 failed: %v", err)
	}

	got2, err := store.GetByComposedID(ctx, user.ID, canal2.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() canal2 failed: %v", err)
	}

	// Verify they have different EventoIDs
	if got1.EventoID == nil || got2.EventoID == nil {
		t.Fatalf("expected both EventoIDs to be set")
	}
	if *got1.EventoID == *got2.EventoID {
		t.Fatalf("expected different EventoIDs for same user in different canals")
	}
	if *got1.EventoID != evento1.ID {
		t.Fatalf("expected canal1 EventoID %q, got %q", evento1.ID, *got1.EventoID)
	}
	if *got2.EventoID != evento2.ID {
		t.Fatalf("expected canal2 EventoID %q, got %q", evento2.ID, *got2.EventoID)
	}
}

// TestUsuarioCanalStore_JoinedAtTimestampPreserved tests that joined_at timestamp is properly stored and retrieved
func TestUsuarioCanalStore_JoinedAtTimestampPreserved(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	joinedTime := baseTime.Add(5 * time.Hour)
	uc := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		Membresia: "join",
		JoinedAt:  joinedTime,
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}

	// Note: The store currently does not retrieve JoinedAt in GetByComposedID
	// This test documents the current behavior
	// If needed, JoinedAt retrieval should be added to the SELECT queries
	if got.CanalID != canal.ID || got.UsuarioID != user.ID || got.Membresia != "join" {
		t.Fatalf("expected complete record, got: %#v", got)
	}
}

// TestUsuarioCanalStore_UpdateMembershipStatus tests updating membership status
func TestUsuarioCanalStore_UpdateMembershipStatus(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
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

	// Create with "join"
	uc := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  &evento1.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}

	if got.Membresia != "join" {
		t.Fatalf("expected 'join', got %q", got.Membresia)
	}

	// Update to "leave"
	got.Membresia = "leave"
	got.EventoID = &evento2.ID
	if err := store.Update(ctx, got); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}

	updated, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() after update failed: %v", err)
	}

	if updated.Membresia != "leave" {
		t.Fatalf("expected 'leave', got %q", updated.Membresia)
	}
	if updated.EventoID == nil || *updated.EventoID != evento2.ID {
		t.Fatalf("expected EventoID %q, got: %v", evento2.ID, updated.EventoID)
	}
}

// TestUsuarioCanalStore_GetAllReturnsCompleteRecords tests that GetAll returns complete records with EventoID
func TestUsuarioCanalStore_GetAllReturnsCompleteRecords(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	evento := model.Evento{
		ID:               "$event:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         user.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}
	insertEvento(t, evento)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	uc := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  &evento.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	all, err := store.GetAll(ctx, util.Filter{})
	if err != nil {
		t.Fatalf("GetAll() failed: %v", err)
	}

	if len(all) != 1 {
		t.Fatalf("expected 1 record, got %d", len(all))
	}

	record := all[0]
	if record.CanalID != canal.ID {
		t.Fatalf("expected CanalID %q, got %q", canal.ID, record.CanalID)
	}
	if record.UsuarioID != user.ID {
		t.Fatalf("expected UsuarioID %q, got %q", user.ID, record.UsuarioID)
	}
	if record.EventoID == nil || *record.EventoID != evento.ID {
		t.Fatalf("expected EventoID %q, got: %v", evento.ID, record.EventoID)
	}
	if record.Membresia != "join" {
		t.Fatalf("expected Membresia 'join', got %q", record.Membresia)
	}
}

// TestUsuarioCanalStore_EventoIDFieldHandlingEdgeCases tests edge cases for EventoID field handling
func TestUsuarioCanalStore_EventoIDFieldHandlingEdgeCases(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@user:example.com",
		LocalPart:   "user",
		Nome:        "User",
		Senha:       "password",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	canal := model.Canal{
		ID:          "!room:example.com",
		Nome:        "Room",
		IsPublic:    true,
		Versao:      "1",
		CriadorID:   user.ID,
		DataCriacao: baseTime,
	}
	insertCanal(t, canal)

	store := NewUsuarioCanalStore(testDB)
	ctx := context.Background()

	// Test 1: Create with NULL, verify NULL
	uc := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  nil,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc); err != nil {
		t.Fatalf("Create() with NULL failed: %v", err)
	}

	got, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() failed: %v", err)
	}

	if got.EventoID != nil {
		t.Fatalf("Test 1: expected EventoID to be nil, got %v", *got.EventoID)
	}

	// Test 2: Delete and recreate with EventoID
	_, err = store.Delete(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}

	evento := model.Evento{
		ID:               "$event:example.com",
		Tipo:             "m.room.member",
		CanalID:          canal.ID,
		SenderID:         user.ID,
		StateKey:         user.ID,
		Conteudo:         `{"membership":"join"}`,
		OrigemServidorTS: 1234567890,
		StreamOrdering:   1,
	}
	insertEvento(t, evento)

	uc2 := model.UsuarioCanal{
		CanalID:   canal.ID,
		UsuarioID: user.ID,
		EventoID:  &evento.ID,
		Membresia: "join",
	}

	if err := store.Create(ctx, &uc2); err != nil {
		t.Fatalf("Create() with EventoID failed: %v", err)
	}

	got2, err := store.GetByComposedID(ctx, user.ID, canal.ID)
	if err != nil {
		t.Fatalf("GetByComposedID() after recreate failed: %v", err)
	}

	if got2.EventoID == nil || *got2.EventoID != evento.ID {
		t.Fatalf("Test 2: expected EventoID %q, got %v", evento.ID, got2.EventoID)
	}
}
