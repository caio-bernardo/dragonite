package roomkeys

import "encoding/json"

// UploadCrossSigningRequest é o corpo de POST /_matrix/client/v3/keys/device_signing/upload
type UploadCrossSigningRequest struct {
	Auth           json.RawMessage `json:"auth,omitempty"`
	MasterKey      json.RawMessage `json:"master_key,omitempty"`
	SelfSigningKey json.RawMessage `json:"self_signing_key,omitempty"`
	UserSigningKey json.RawMessage `json:"user_signing_key,omitempty"`
}

// UploadSignaturesRequest é o corpo de POST /_matrix/client/v3/keys/signatures/upload:
// mapa de userID -> keyID -> objeto assinado completo
type UploadSignaturesRequest map[string]map[string]json.RawMessage

// UploadSignaturesResponse é a resposta 200 de POST /_matrix/client/v3/keys/signatures/upload
type UploadSignaturesResponse struct {
	Failures map[string]map[string]any `json:"failures"`
}

// CrossSigningKeyInfo é o formato de uma chave de cross-signing retornada em /keys/query
type CrossSigningKeyInfo struct {
	Keys       json.RawMessage `json:"keys"`
	Signatures json.RawMessage `json:"signatures,omitempty"`
	Usage      []string        `json:"usage"`
	UserID     string          `json:"user_id"`
}
