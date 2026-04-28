package client

type SupportedVersionsResponse struct {
	Versions         []string        `json:"versions"`
	UnstableFeatures map[string]bool `json:"unstable_features,omitempty"`
}

// Corpo da requisição POST /_matrix/client/v3/user_directory/search
type UserSearchRequest struct {
	SearchTerm string `json:"search_term"`         // obrigatório pela spec
	Limit      int    `json:"limit"`
}

// Um usuário retornado na busca
type UserSearchResult struct {
	UserID      string `json:"user_id"`            // obrigatório
	DisplayName string `json:"display_name,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
}

// Resposta ao POST /_matrix/client/v3/user_directory/search
type UserSearchResponse struct {
	Limited bool               `json:"limited"`    // obrigatório, true se resultados foram truncados pelo limite
	Results []UserSearchResult `json:"results"`    // obrigatório
}
