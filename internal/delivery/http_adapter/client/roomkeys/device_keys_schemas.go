package roomkeys

import "encoding/json"

// DeviceKeysUpload é o objeto "device_keys" enviado em POST /_matrix/client/v3/keys/upload
type DeviceKeysUpload struct {
	Algorithms []string        `json:"algorithms"`
	DeviceID   string          `json:"device_id"`
	Keys       json.RawMessage `json:"keys"`
	Signatures json.RawMessage `json:"signatures"`
	UserID     string          `json:"user_id"`
}

// UploadKeysRequest é o corpo de POST /_matrix/client/v3/keys/upload
type UploadKeysRequest struct {
	DeviceKeys   *DeviceKeysUpload          `json:"device_keys,omitempty"`
	OneTimeKeys  map[string]json.RawMessage `json:"one_time_keys,omitempty"`
	FallbackKeys map[string]json.RawMessage `json:"fallback_keys,omitempty"`
}

// UploadKeysResponse é a resposta 200 de POST /_matrix/client/v3/keys/upload
type UploadKeysResponse struct {
	OneTimeKeyCounts map[string]int `json:"one_time_key_counts"`
}

// UnsignedDevice contém dados adicionais não cobertos pela assinatura do dispositivo
type UnsignedDevice struct {
	DeviceDisplayName string `json:"device_display_name,omitempty"`
}

// DeviceKeysInfo é o formato de um dispositivo retornado em POST /_matrix/client/v3/keys/query
type DeviceKeysInfo struct {
	Algorithms []string        `json:"algorithms"`
	DeviceID   string          `json:"device_id"`
	Keys       json.RawMessage `json:"keys"`
	Signatures json.RawMessage `json:"signatures"`
	UserID     string          `json:"user_id"`
	Unsigned   UnsignedDevice  `json:"unsigned,omitempty"`
}

// QueryKeysRequest é o corpo de POST /_matrix/client/v3/keys/query
type QueryKeysRequest struct {
	DeviceKeys map[string][]string `json:"device_keys"`
	Timeout    int                 `json:"timeout,omitempty"`
}

// QueryKeysResponse é a resposta 200 de POST /_matrix/client/v3/keys/query
type QueryKeysResponse struct {
	DeviceKeys      map[string]map[string]DeviceKeysInfo `json:"device_keys"`
	MasterKeys      map[string]CrossSigningKeyInfo       `json:"master_keys,omitempty"`
	SelfSigningKeys map[string]CrossSigningKeyInfo       `json:"self_signing_keys,omitempty"`
	UserSigningKeys map[string]CrossSigningKeyInfo       `json:"user_signing_keys,omitempty"`
	Failures        map[string]any                       `json:"failures"`
}

// ClaimKeysRequest é o corpo de POST /_matrix/client/v3/keys/claim
type ClaimKeysRequest struct {
	OneTimeKeys map[string]map[string]string `json:"one_time_keys"`
	Timeout     int                          `json:"timeout,omitempty"`
}

// ClaimKeysResponse é a resposta 200 de POST /_matrix/client/v3/keys/claim
type ClaimKeysResponse struct {
	OneTimeKeys map[string]map[string]map[string]json.RawMessage `json:"one_time_keys"`
	Failures    map[string]any                                   `json:"failures"`
}

// KeyChangesResponse é a resposta 200 de GET /_matrix/client/v3/keys/changes
type KeyChangesResponse struct {
	Changed []string `json:"changed"`
	Left    []string `json:"left"`
}
