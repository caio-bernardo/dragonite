package types

// AuthenticationData holds the session and type of authentication
type AuthenticationData struct {
	Session string `json:"session"`
	Type    string `json:"type"`
	any
}
