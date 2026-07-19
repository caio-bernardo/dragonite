package domain

import "encoding/json"

// ToDeviceMessage representa uma mensagem send-to-device pendente de entrega a um dispositivo local
type ToDeviceMessage struct {
	ID       int64
	UserID   string // dono do dispositivo destinatário (sempre local)
	DeviceID string
	Sender   string // Matrix user ID de quem enviou (pode ser remoto)
	Type     string
	Content  json.RawMessage
}
