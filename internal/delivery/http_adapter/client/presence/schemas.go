package presence

// PresenceStatusResponse é o corpo da resposta 200 de GET /_matrix/client/v3/presence/{userId}/status
type PresenceStatusResponse struct {
	CurrentlyActive bool    `json:"currently_active"`
	LastActiveAgo   int64   `json:"last_active_ago"`
	Presence        string  `json:"presence"`
	StatusMsg       *string `json:"status_msg,omitempty"`
}

// PresenceStatusRequest é o corpo da requisição de PUT /_matrix/client/v3/presence/{userId}/status
type PresenceStatusRequest struct {
	Presence  string  `json:"presence"`
	StatusMsg *string `json:"status_msg,omitempty"`
}