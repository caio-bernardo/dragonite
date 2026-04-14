package auth

import "github.com/caio-bernardo/dragonite/internal/types"

// LoginFlowsReponse represents reponse body for GET /login, showing supported authenticatin methods
type LoginFlowsReponse struct {
	Flows []Flow `json:"flows"` // versão suportada
}

// Flow represents a type of authentication flow
type Flow struct {
	GetLoginToken *bool                    `json:"get_login_token,omitempty"`
	Type          types.AuthenticationType `json:"type"`
}

// LoginRequest represents body for POST /login
type LoginRequest struct {
	Type                     string                `json:"type"`
	Identifier               types.UserIndentifier `json:"identifier"`
	Password                 string                `json:"password,omitempty"`
	Token                    string                `json:"token,omitempty"`
	DeviceID                 string                `json:"device_id,omitempty"`
	InitialDeviceDisplayName string                `json:"initial_device_display_name,omitempty"`
}

// LoginReponse represents a response body for POST /login
type LoginReponse struct {
	AccessToken  string `json:"access_token"`
	DeviceID     string `json:"device_id"`
	UserID       string `json:"user_id"`
	ExpireMS     *int   `json:"expire_ms,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// TODO: add Identity server information
}
