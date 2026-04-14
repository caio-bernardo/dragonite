package types

// AuthenticationType represents the type of authentication used for login
type AuthenticationType string

const (
	// Password-based
	AuthenticationTypePassword AuthenticationType = "m.login.password"

	// Recaptcha-based
	AuthenticationTypeRecaptcha AuthenticationType = "m.login.recaptcha"

	// Oauth2
	AuthenticationTypeOauth2 AuthenticationType = "m.login.oauth2"

	// Email-based
	AuthenticationTypeEmail AuthenticationType = "m.login.email.identity"

	// Token-based
	AuthenticationTypeToken AuthenticationType = "m.login.token"

	// Dummy Auth
	AuthenticationTypeDummy AuthenticationType = "m.login.dummy"
)
