package client

import (
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
)

type SupportedVersionsResponse struct {
	Versions         []string        `json:"versions"`
	UnstableFeatures map[string]bool `json:"unstable_features,omitempty"`
}

// Resposta mockada de GET /_matrix/client/v3/pushrules/
type PushRulesResponse struct {
	Global map[string]any `json:"global"`
}

// Resposta mockada de POST /_matrix/client/v3/user/{userId}/filter
type FilterUploadResponse struct {
	FilterID string `json:"filter_id"`
}

// Resposta de GET /_matrix/client/v3/capabilities (mock — só inclui m.room_versions)
type CapabilitiesResponse struct {
	Capabilities Capabilities `json:"capabilities"`
}

type Capabilities struct {
	RoomVersions RoomVersionsCapability `json:"m.room_versions"`
}

type RoomVersionsCapability struct {
	Default   string            `json:"default"`   // obrigatório
	Available map[string]string `json:"available"` // obrigatório
}

// Corpo da requisição POST /_matrix/client/v3/user_directory/search
type UserSearchRequest struct {
	SearchTerm string `json:"search_term"` // obrigatório pela spec
	Limit      int    `json:"limit"`
}

// Um usuário retornado na busca
type UserSearchResult struct {
	UserID      string `json:"user_id"` // obrigatório
	DisplayName string `json:"display_name,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
}

// Resposta ao POST /_matrix/client/v3/user_directory/search
type UserSearchResponse struct {
	Limited bool               `json:"limited"` // obrigatório, true se resultados foram truncados pelo limite
	Results []UserSearchResult `json:"results"` // obrigatório
}

// Controla se o cliente é automaticamente marcado como online ao usar a API
type SetPresence string

const (
	PresenceOnline      SetPresence = "online"
	PresenceOffline     SetPresence = "offline"
	PresenceUnavailable SetPresence = "unavailable"
)

// Requisição (parametros na verdade) de /_matrix/client/v3/sync
type SyncClientRequest struct {
	Filter      string           `json:"filter,omitempty"`
	Since       domain.SyncToken `json:"since,omitempty"`
	FullState   bool             `json:"full_state,omitempty"`
	SetPresence SetPresence      `json:"set_presence,omitempty"`
	Timeout     time.Duration    `json:"timeout,omitempty"`
}

// Essa struct representa o perfil completo
type ProfileResponse struct {
	DisplayName string `json:"displayname,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
}

// DisplayNameRequest representa a requisição/resposta para displayname
type DisplayNameRequest struct {
	DisplayName string `json:"displayname"`
}

// GET /_matrix/client/v3/joined_rooms
type JoinedRoomsResponse struct {
	JoinedRooms []string `json:"joined_rooms"`
}

// GET /_matrix/client/v3/directory/room/{roomAlias} resposta
type RoomAliasResponse struct {
	RoomID  string   `json:"room_id"`
	Servers []string `json:"servers"`
}

// PUT /_matrix/client/v3/directory/room/{roomAlias} corpo da requisição
type SetRoomAliasRequest struct {
	RoomID string `json:"room_id"`
}

// QueryKeysRequest representa o corpo da requisição enviada pelo Element
type QueryKeysRequest struct {
	DeviceKeys map[string][]string `json:"device_keys"`
	Timeout    int                 `json:"timeout,omitempty"`
	Token      string              `json:"token,omitempty"`
}
