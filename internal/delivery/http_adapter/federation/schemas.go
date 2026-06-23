package federation

import "github.com/caio-bernardo/dragonite/internal/domain"

type VersionResponse struct {
	Server struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"server"`
}

type ServerKeyResponse struct {
	OldVerifyKeys map[string]VerifyKey         `json:"old_verify_keys,omitempty"`
	ServerName    string                       `json:"server_name"`
	Signatures    map[string]map[string]string `json:"signatures"`
	ValidUntilTS  int64                        `json:"valid_until_ts"`
	VerifyKeys    map[string]VerifyKey         `json:"verify_keys"`
}

type VerifyKey struct {
	Key       string `json:"key"`
	ExpiredTS int64  `json:"expired_ts,omitzero"`
}

type TransactionRequest struct {
	Origin         string          `json:"origin"`
	OriginServerTS string          `json:"origin_server_ts"`
	PDUs           []domain.Evento `json:"pdus"`
}

// Response format is the same as request
type TransactionResponse struct {
	Origin         string          `json:"origin"`
	OriginServerTS int64           `json:"origin_server_ts"`
	PDUs           []domain.Evento `json:"pdus"`
}

type StateResponse struct {
	AuthChain []domain.Evento `json:"auth_chain"`
	PDUs      []domain.Evento `json:"pdus"`
}
