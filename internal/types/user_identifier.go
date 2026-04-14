package types

// UserIndentifier represents a user identifier used for login
type UserIndentifier struct {
	Type IdentifierType `json:"type"`
	User string         `json:"user,omitempty"`
}

// IdentifierType represents the type of user identifier, like username, phone number or other thirdparty indentifiers
type IdentifierType string

const (
	// username
	IdentifierTypeUser IdentifierType = "m.id.user"
	// TODO: add thirdparty and phone
)
