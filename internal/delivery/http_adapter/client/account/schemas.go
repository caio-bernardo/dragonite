package account

// WhoamiResponse representa o corpo de resposta de GET /account/whoami
type WhoamiResponse struct {
	DeviceID string `json:"device_id,omitempty"`
	IsGuest  bool   `json:"is_guest,omitempty"` // TODO: preencher quando houver suporte a contas guest
	UserID   string `json:"user_id"`
}