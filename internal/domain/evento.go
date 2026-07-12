package domain

import (
	"encoding/json"
)

type Evento struct {
	ID               string          `json:"id"`
	Tipo             string          `json:"type"`
	Content          json.RawMessage `json:"content"`
	CanalID          string          `json:"room_id"`
	Sender           string          `json:"sender"`
	OrigemServidorTS int64           `json:"origin_server_ts"`

	StreamOrdering int64 `json:"-"` // NOTE: campo interno, não deve ser exposto ao cliente

	StateKey *string `json:"state_key"`
	Redacts  string  `json:"redacts"`

	PrevEventos []string `json:"prev_events"`
	AuthEventos []string `json:"auth_events"`
	Depth       int64    `json:"depth"`

	Hashes     json.RawMessage `json:"hashes"`
	Signatures json.RawMessage `json:"signature"`
	Unsigned   json.RawMessage `json:"unsigned"` // dados adicionados pelo servidor
}

type StrippedEvento struct {
	Tipo     string          `json:"type"`
	Content  json.RawMessage `json:"content"`
	StateKey *string         `json:"state_key"`
	Sender   string          `json:"sender"`
}
