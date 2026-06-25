package federation

import (
	"encoding/json"

	"github.com/caio-bernardo/dragonite/internal/domain"
)

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

// publicRooms

type PublicRoomsFilter struct {
	GenericSearchTerm string    `json:"generic_search_term,omitempty"`
	RoomTypes         []*string `json:"room_types,omitempty"`
}

type PublicRoomsRequest struct {
	Filter               *PublicRoomsFilter `json:"filter,omitempty"`
	IncludeAllNetworks   bool               `json:"include_all_networks,omitempty"`
	Limit                int                `json:"limit,omitempty"`
	Since                string             `json:"since,omitempty"`
	ThirdPartyInstanceID string             `json:"third_party_instance_id,omitempty"`
}

// make_join

type MembershipContent struct {
	JoinAuthorisedViaUsersServer string `json:"join_authorised_via_users_server,omitempty"`
	Membership                   string `json:"membership"`
}

type EventTemplate struct {
	Content        MembershipContent `json:"content"`
	Origin         string            `json:"origin"`
	OriginServerTS int64             `json:"origin_server_ts"`
	RoomID         string            `json:"room_id"`
	Sender         string            `json:"sender"`
	StateKey       string            `json:"state_key"`
	Type           string            `json:"type"`
}

type MakeJoinResponse struct {
	Event       EventTemplate `json:"event"`
	RoomVersion string        `json:"room_version"`
}

// send_join

type SendJoinRequest struct {
	Content        MembershipContent            `json:"content"`
	Origin         string                       `json:"origin"`
	OriginServerTS int64                        `json:"origin_server_ts"`
	Sender         string                       `json:"sender"`
	StateKey       string                       `json:"state_key"`
	Type           string                       `json:"type"`
	RoomID         string                       `json:"room_id"`
	EventID        string                       `json:"event_id"`
	Signatures     map[string]map[string]string `json:"signatures"`
}

type SendJoinResponse struct {
	AuthChain     []domain.Evento `json:"auth_chain"`
	State         []domain.Evento `json:"state"`
	ServersInRoom []string        `json:"servers_in_room,omitempty"`
}

type StrippedStateEvent struct {
	Content  json.RawMessage `json:"content"`
	StateKey string          `json:"state_key"`
	Type     string          `json:"type"`
	Sender   string          `json:"sender"`
}

// make_leave

type MakeLeaveResponse struct {
	Event       EventTemplate `json:"event"`
	RoomVersion string        `json:"room_version"`
}

// send_leave

type SendLeaveRequest struct {
	Content        MembershipContent            `json:"content"`
	Origin         string                       `json:"origin"`
	OriginServerTS int64                        `json:"origin_server_ts"`
	Sender         string                       `json:"sender"`
	StateKey       string                       `json:"state_key"`
	Type           string                       `json:"type"`
	RoomID         string                       `json:"room_id"`
	EventID        string                       `json:"event_id"`
	Signatures     map[string]map[string]string `json:"signatures"`
}

type InviteRequest struct {
	RoomVersion     string               `json:"room_version"`
	Event           json.RawMessage      `json:"event"`
	InviteRoomState []StrippedStateEvent `json:"invite_room_state"`
}

type InviteResponse struct {
	Event json.RawMessage `json:"event"`
}
