package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type Usuario struct {
	ID          string
	LocalPart   string
	SenhaHash   []byte
	DataCriacao time.Time
}

type Profile struct {
	IDUsuario   string  `json:"-"`
	DisplayName *string `json:"displayname,omitempty"`
	AvatarURL   *string `json:"avatar_url,omitempty"`
}

type AccountData struct {
	IDUsuario string          `json:"-"`
	IDCanal   string          `json:"-"`
	Tipo      string          `json:"type"`
	Content   json.RawMessage `json:"content"`
}

type Dispositivo struct {
	ID                    uuid.UUID `json:"device_id"`
	Nome                  string    `json:"device_name"`
	UsuarioID             string    `json:"userd_id"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	UltimoIPVisto         string    `json:"last_seen_ip"`
	UltimoTimestampVisto  time.Time `json:"last_seen_ts"`
}
