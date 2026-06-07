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
	IDCanal   string          `json:"id_canal,omitempty"`
	Tipo      string          `json:"tipo,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
}

type Dispositivo struct {
	ID                    uuid.UUID `json:"id_dispositivo"`
	Nome                  string    `json:"nome_dispositivo"`
	UsuarioID             string    `json:"usuario_id"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	UltimoIPVisto         string    `json:"ultimo_ip_visto"`
	UltimoTimestampVisto  time.Time `json:"ultimo_timestamp_visto"`
}
