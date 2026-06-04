package repository

import (
	"context"
	"errors"
	"testing"
	"time"
	"fmt"
	

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
		EventoID:  &evento.ID,
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

func TestCanalStore_ListPublic_Pagination(t *testing.T) {
	resetTables(t)

	owner := model.Usuario{
		ID: "@page-owner:example.com", LocalPart: "page-owner",
		Nome: "Owner", Senha: "password", DataCriacao: baseTime,
	}
	insertUsuario(t, owner)

	store := NewChannelStore(testDB)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		c := model.Canal{
			ID:                fmt.Sprintf("!page-room%d:example.com", i),
			LocalPart:         fmt.Sprintf("page-room%d", i),
			ServerName:        "example.com",
			Nome:              fmt.Sprintf("Page Room %d", i),
			IsPublic:          true,
			JoinRules:         "public",
			GuestAccess:       "forbidden",
			HistoryVisibility: "shared",
			Versao:            "11",
			CriadorID:         owner.ID,
			MemberCount:       i,
			DataCriacao:       baseTime,
		}
		if err := store.Create(ctx, &c); err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
	}

	// Primeira página: limit=2
	page1, nextBatch, prevBatch, total, err := store.ListPublic(ctx, ListPublicParams{Limit: 2})
	if err != nil {
		t.Fatalf("ListPublic() page 1 failed: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("expected 2 canais na página 1, got %d", len(page1))
	}
	if nextBatch == "" {
		t.Fatal("expected nextBatch na página 1")
	}
	if prevBatch != "" {
		t.Fatalf("expected empty prevBatch na página 1, got %q", prevBatch)
	}
	if total != 3 {
		t.Fatalf("expected total 3, got %d", total)
	}

	// Segunda página usando o token retornado
	page2, nextBatch2, prevBatch2, _, err := store.ListPublic(ctx, ListPublicParams{Limit: 2, SinceToken: nextBatch})
	if err != nil {
		t.Fatalf("ListPublic() page 2 failed: %v", err)
	}
	if len(page2) != 1 {
		t.Fatalf("expected 1 canal na página 2, got %d", len(page2))
	}
	if nextBatch2 != "" {
		t.Fatalf("expected empty nextBatch na página 2, got %q", nextBatch2)
	}
	if prevBatch2 == "" {
		t.Fatal("expected prevBatch na página 2")
	}
}

func TestCanalStore_ListPublic_SearchTerm(t *testing.T) {
	resetTables(t)

	owner := model.Usuario{
		ID: "@search-owner:example.com", LocalPart: "search-owner",
		Nome: "Owner", Senha: "password", DataCriacao: baseTime,
	}
	insertUsuario(t, owner)

	store := NewChannelStore(testDB)
	ctx := context.Background()

	cheese := model.Canal{
		ID: "!cheese:example.com", LocalPart: "cheese", ServerName: "example.com",
		Nome: "Cheese Lovers", Descricao: "All about cheese", IsPublic: true,
		JoinRules: "public", GuestAccess: "forbidden", HistoryVisibility: "shared",
		Versao: "11", CriadorID: owner.ID, MemberCount: 10, DataCriacao: baseTime,
	}
	other := model.Canal{
		ID: "!other:example.com", LocalPart: "other", ServerName: "example.com",
		Nome: "Unrelated Room", Descricao: "Nothing here", IsPublic: true,
		JoinRules: "public", GuestAccess: "forbidden", HistoryVisibility: "shared",
		Versao: "11", CriadorID: owner.ID, MemberCount: 2, DataCriacao: baseTime,
	}
	for _, c := range []model.Canal{cheese, other} {
		if err := store.Create(ctx, &c); err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
	}

	canais, _, _, total, err := store.ListPublic(ctx, ListPublicParams{SearchTerm: "cheese"})
	if err != nil {
		t.Fatalf("ListPublic() with search failed: %v", err)
	}
	if len(canais) != 1 {
		t.Fatalf("expected 1 canal, got %d", len(canais))
	}
	if canais[0].ID != cheese.ID {
		t.Fatalf("expected cheese room, got %s", canais[0].ID)
	}
	if total != 1 {
		t.Fatalf("expected total 1, got %d", total)
	}
}

func TestCanalStore_ListPublic(t *testing.T) {
	resetTables(t)

	owner := model.Usuario{
		ID: "@list-owner:example.com", LocalPart: "list-owner",
		Nome: "Owner", Senha: "password", DataCriacao: baseTime,
	}
	insertUsuario(t, owner)

	store := NewChannelStore(testDB)
	ctx := context.Background()

	c1 := model.Canal{
		ID: "!room1:example.com", LocalPart: "room1", ServerName: "example.com",
		Nome: "Room 1", IsPublic: true, JoinRules: "public", GuestAccess: "forbidden",
		HistoryVisibility: "shared", Versao: "11", CriadorID: owner.ID,
		MemberCount: 1, DataCriacao: baseTime,
	}
	c2 := model.Canal{
		ID: "!room2:example.com", LocalPart: "room2", ServerName: "example.com",
		Nome: "Room 2", IsPublic: true, JoinRules: "public", GuestAccess: "forbidden",
		HistoryVisibility: "shared", Versao: "11", CriadorID: owner.ID,
		MemberCount: 5, DataCriacao: baseTime,
	}

	for _, c := range []model.Canal{c1, c2} {
		if err := store.Create(ctx, &c); err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
	}

	canais, nextBatch, prevBatch, total, err := store.ListPublic(ctx, ListPublicParams{Limit: 10})
	if err != nil {
		t.Fatalf("ListPublic() failed: %v", err)
	}
	if len(canais) != 2 {
		t.Fatalf("expected 2 canais, got %d", len(canais))
	}
	// Ordenado por member_count DESC
	if canais[0].ID != c2.ID {
		t.Fatalf("expected canal with more members first")
	}
	if nextBatch != "" {
		t.Fatalf("expected empty nextBatch, got %q", nextBatch)
	}
	if prevBatch != "" {
		t.Fatalf("expected empty prevBatch, got %q", prevBatch)
	}
	if total != 2 {
		t.Fatalf("expected total 2, got %d", total)
	}
}

func TestCanalStore_GetByID_NotFound(t *testing.T) {
	resetTables(t)

	store := NewChannelStore(testDB)
	_, err := store.GetByID(context.Background(), "!naoexiste:example.com")
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestCanalStore_UpdateMemberCount(t *testing.T) {
	resetTables(t)

	owner := model.Usuario{
		ID: "@count-owner:example.com", LocalPart: "count-owner",
		Nome: "Owner", Senha: "password", DataCriacao: baseTime,
	}
	insertUsuario(t, owner)

	store := NewChannelStore(testDB)
	ctx := context.Background()

	canal := model.Canal{
		ID: "!count-room:example.com", LocalPart: "count-room", ServerName: "example.com",
		Nome: "Count Room", IsPublic: true, JoinRules: "public", GuestAccess: "forbidden",
		HistoryVisibility: "shared", Versao: "11", CriadorID: owner.ID,
		MemberCount: 1, DataCriacao: baseTime,
	}
	if err := store.Create(ctx, &canal); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	if err := store.UpdateMemberCount(ctx, canal.ID, +1); err != nil {
		t.Fatalf("UpdateMemberCount(+1) failed: %v", err)
	}

	got, _ := store.GetByID(ctx, canal.ID)
	if got.MemberCount != 2 {
		t.Fatalf("expected MemberCount 2, got %d", got.MemberCount)
	}
}