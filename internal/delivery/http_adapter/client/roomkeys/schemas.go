package roomkeys

import (
	"encoding/json"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
)

// CreateBackupVersionRequest é o corpo da requisição POST /_matrix/client/v3/room_keys/version
type CreateBackupVersionRequest struct {
	Algorithm string          `json:"algorithm"`
	AuthData  json.RawMessage `json:"auth_data"`
}

// CreateBackupVersionResponse é o corpo da resposta 200 de POST /_matrix/client/v3/room_keys/version
type CreateBackupVersionResponse struct {
	Version string `json:"version"`
}

// BackupVersionResponse é o corpo da resposta 200 de GET /_matrix/client/v3/room_keys/version
type BackupVersionResponse struct {
	Algorithm string          `json:"algorithm"`
	AuthData  json.RawMessage `json:"auth_data"`
	Count     int64           `json:"count"`
	ETag      string          `json:"etag"`
	Version   string          `json:"version"`
}

// RoomKeyBackupData é o dado de uma única sessão armazenada no backup
type RoomKeyBackupData struct {
	FirstMessageIndex int64           `json:"first_message_index"`
	ForwardedCount    int64           `json:"forwarded_count"`
	IsVerified        bool            `json:"is_verified"`
	SessionData       json.RawMessage `json:"session_data"`
}

// RoomKeyBackup agrupa as sessões de uma sala dentro do backup
type RoomKeyBackup struct {
	Sessions map[string]RoomKeyBackupData `json:"sessions"`
}

// GetRoomKeysResponse é o corpo da resposta 200 de GET /_matrix/client/v3/room_keys/keys
type GetRoomKeysResponse struct {
	Rooms map[string]RoomKeyBackup `json:"rooms"`
}

// PutRoomKeysRequest é o corpo da requisição PUT /_matrix/client/v3/room_keys/keys
type PutRoomKeysRequest struct {
	Rooms map[string]RoomKeyBackup `json:"rooms"`
}

// RoomKeysUpdateResponse é o corpo da resposta 200 de PUT/DELETE /_matrix/client/v3/room_keys/keys
type RoomKeysUpdateResponse struct {
	Count int64  `json:"count"`
	ETag  string `json:"etag"`
}

// WrongVersionErrorResponse é o corpo do erro 403 M_WRONG_ROOM_KEYS_VERSION
type WrongVersionErrorResponse struct {
	ErrCode        httputil.MatrixErrorCode `json:"errcode"`
	Message        string                   `json:"error"`
	CurrentVersion string                   `json:"current_version"`
}
