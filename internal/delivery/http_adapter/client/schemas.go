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
