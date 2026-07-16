package domain

import (
	"encoding/json"
)

type Evento struct {
	ID               string          `json:"event_id"`
	Tipo             string          `json:"type"`
	Content          json.RawMessage `json:"content"`
	CanalID          string          `json:"room_id"`
	Sender           string          `json:"sender"`
	OrigemServidorTS int64           `json:"origin_server_ts"`

	StreamOrdering int64 `json:"-"` // NOTE: campo interno, não deve ser exposto ao cliente

	StateKey *string `json:"state_key,omitempty"`
	Redacts  string  `json:"redacts,omitempty"`

	PrevEventos []string `json:"prev_events,omitempty"`
	AuthEventos []string `json:"auth_events,omitempty"`
	Depth       int64    `json:"depth,omitempty"`

	Hashes     json.RawMessage `json:"hashes,omitempty"`
	Signatures json.RawMessage `json:"signature,omitempty"`
	Unsigned   json.RawMessage `json:"unsigned,omitempty"` // dados adicionados pelo servidor
}

type StrippedEvento struct {
	Tipo     string          `json:"type"`
	Content  json.RawMessage `json:"content"`
	StateKey *string         `json:"state_key,omitempty"`
	Sender   string          `json:"sender"`
}
