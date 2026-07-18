package domain

import "time"

// PresenceState representa o estado de presença de um usuário no Matrix
type PresenceState string

const (
	PresenceOnline      PresenceState = "online"
	PresenceOffline     PresenceState = "offline"
	PresenceUnavailable PresenceState = "unavailable"
)

// Presence representa o estado de presença atual de um usuário: se está online,
// há quanto tempo, e uma mensagem de status livre (ex: "Farmando aura")
// não faz parte da DAG de eventos de nenhuma sala
type Presence struct {
	IDUsuario    string
	State        PresenceState
	StatusMsg    *string
	LastActiveAt time.Time
}
