package model

type Evento struct {
	ID               string `json:"id_evento"`
	Tipo             string `json:"tipo_evento"`
	CanalID          string `json:"id_canal"`
	SenderID         string `json:"id_sender"`
	StateKey         string `json:"state_key"`
	Conteudo         string `json:"conteudo"`
	OrigemServidorTS int64  `json:"origem_servidor_ts"`
	StreamOrdering   int64  `json:"stream_ordering"`
	TxnID            *string `json:"txn_id,omitempty"`
}

type ArestaEvento struct {
	EventoID           string `json:"id_evento"`
	EventoAntecessorID string `json:"id_evento_antecessor"`
	CanalID            string `json:"id_canal"`
	IsState            bool   `json:"is_state"`
}

// EventoPublic é o modelo do evento compativel com o protocolo Matrix
type EventoPublic struct {
	Type           string `json:"type"`
	EventID        string `json:"event_id"`
	Sender         string `json:"sender"`
	OriginServerTS int64  `json:"origin_server_ts"`
	Content        string `json:"content"`
	StateKey       string `json:"state_key,omitempty"`
	RoomID         string `json:"room_id,omitempty"`
}
