package client

import (
	"encoding/json"
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

// Resposta GET /_matrix/client/v3/sync
type SyncClientResponse struct {
	NextBatch domain.SyncToken `json:"next_batch"`
	Rooms     RoomsSync        `json:"rooms,omitempty"`
}

type RoomsSync struct {
	Join   map[string]JoinedRoom  `json:"join"`
	Invite map[string]InvitedRoom `json:"invite"`
	Leave  map[string]LeftRoom    `json:"leave"`
}

type JoinedRoom struct {
	State    State    `json:"state,omitempty"`
	Timeline Timeline `json:"timeline,omitempty"`
}

type State struct {
	Events []json.RawMessage `json:"events,omitempty"`
}

type Timeline struct {
	Events    []json.RawMessage `json:"events,omitempty"`
	Limited   bool              `json:"limited,omitempty"`
	PrevBatch domain.SyncToken  `json:"prev_batch,omitempty"`
}

type InvitedRoom struct {
	InviteState InviteState `json:"invate_state"`
}

type InviteState struct {
	Events []json.RawMessage `json:"events,omitempty"`
}

type LeftRoom struct {
	State    State    `json:"state,omitempty"`
	Timeline Timeline `json:"timeline,omitempty"`
}

// Cria uma nova resposta de sincronização com valores padrão.
func createSyncResponse() SyncClientResponse {
	return SyncClientResponse{
		NextBatch: domain.SyncToken{},
		Rooms: RoomsSync{
			Join:   make(map[string]JoinedRoom),
			Invite: make(map[string]InvitedRoom),
			Leave:  make(map[string]LeftRoom),
		},
	}
}

func encodeEventsIntoResponse(events []domain.Evento, token domain.SyncToken) SyncClientResponse {
	response := createSyncResponse()

	// Mapa temporário para agrupar os eventos por ID da sala (CanalID)
	roomTimelines := make(map[string][]json.RawMessage)

	for _, e := range events {
		clientEv := domain.Evento{
			Tipo:             e.Tipo,
			ID:               e.ID,
			Sender:           e.Sender,
			OrigemServidorTS: e.OrigemServidorTS,
			Content:          e.Content,
			StateKey:         e.StateKey,
		}

		// Usamos json.RawMessage no SyncResponse para evitar parse redundante
		eventBytes, err := json.Marshal(clientEv)
		if err != nil {
			// ignora falhas
			continue
		}

		roomTimelines[e.CanalID] = append(roomTimelines[e.CanalID], eventBytes)
	}

	for roomID, eventsJSON := range roomTimelines {
		response.Rooms.Join[roomID] = JoinedRoom{
			Timeline: Timeline{
				Events:  eventsJSON,
				Limited: false,
			},
		}
	}
	response.NextBatch = token
	return response
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
