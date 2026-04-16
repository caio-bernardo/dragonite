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

func TestDispositivoStoreCRUDAndUpsert(t *testing.T) {
	resetTables(t)

	user := model.Usuario{
		ID:          "@device-owner:example.com",
		LocalPart:   "device-owner",
		Nome:        "Device Owner",
		Senha:       "password",
		Foto:        "https://example.com/device-owner.png",
		DataCriacao: baseTime,
	}
	insertUsuario(t, user)

	store := NewDispositivoStore(testDB)
	ctx := context.Background()

	device := model.Dispositivo{
		ID:                    "00000000-0000-0000-0000-000000000001",
		UsuarioID:             user.ID,
		Nome:                  "Laptop",
		RefreshToken:          "refresh-token-1",
		RefreshTokenExpiresAt: baseTime.Add(24 * time.Hour),
		UltimoIPVisto:         "127.0.0.1",
		UltimoTimestampVisto:  baseTime.Add(2 * time.Hour),
	}

	if err := store.Create(ctx, &device); err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	got, err := store.GetByID(ctx, device.ID)
	if err != nil {
		t.Fatalf("GetByID() failed: %v", err)
	}
	if got.ID != device.ID || got.UsuarioID != device.UsuarioID || got.Nome != device.Nome || got.RefreshToken != device.RefreshToken {
		t.Fatalf("GetByID() returned unexpected device: %#v", got)
	}
	if !got.RefreshTokenExpiresAt.Equal(device.RefreshTokenExpiresAt) || !got.UltimoTimestampVisto.Equal(device.UltimoTimestampVisto) {
		t.Fatalf("GetByID() returned unexpected timestamps: %#v", got)
	}

	all, err := store.GetAll(ctx, util.Filter{})
	if err != nil {
		t.Fatalf("GetAll() failed: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("GetAll() expected 1 device, got %d", len(all))
	}

	updated := device
	updated.Nome = "Laptop Updated"
	updated.RefreshToken = "refresh-token-2"
	updated.RefreshTokenExpiresAt = baseTime.Add(48 * time.Hour)
	updated.UltimoIPVisto = "10.0.0.1"
	updated.UltimoTimestampVisto = baseTime.Add(3 * time.Hour)

	if err := store.Update(ctx, &updated); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}

	gotUpdated, err := store.GetByID(ctx, device.ID)
	if err != nil {
		t.Fatalf("GetByID() after update failed: %v", err)
	}
	if gotUpdated.Nome != updated.Nome || gotUpdated.RefreshToken != updated.RefreshToken || gotUpdated.UltimoIPVisto != updated.UltimoIPVisto {
		t.Fatalf("Update() did not persist changes: %#v", gotUpdated)
	}

	upserted := device
	upserted.Nome = "Laptop Upserted"
	upserted.RefreshToken = "refresh-token-3"
	upserted.RefreshTokenExpiresAt = baseTime.Add(72 * time.Hour)

	if err := store.CreateOrUpdate(ctx, &upserted); err != nil {
		t.Fatalf("CreateOrUpdate() failed: %v", err)
	}

	gotUpserted, err := store.GetByID(ctx, device.ID)
	if err != nil {
		t.Fatalf("GetByID() after upsert failed: %v", err)
	}
	if gotUpserted.Nome != upserted.Nome || gotUpserted.RefreshToken != upserted.RefreshToken {
		t.Fatalf("CreateOrUpdate() did not persist changes: %#v", gotUpserted)
	}

	deleted, err := store.Delete(ctx, device.ID)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	if deleted.ID != device.ID {
		t.Fatalf("Delete() returned unexpected device: %#v", deleted)
	}

	if _, err := store.GetByID(ctx, device.ID); !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}
