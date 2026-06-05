package federation

import (
	"encoding/json"
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

type PublishedRoomsChunk struct {
    AvatarURL        string `json:"avatar_url,omitempty"`
    CanonicalAlias   string `json:"canonical_alias,omitempty"`
    GuestCanJoin     bool   `json:"guest_can_join"`
    JoinRule         string `json:"join_rule,omitempty"`
    Name             string `json:"name,omitempty"`
    NumJoinedMembers int    `json:"num_joined_members"`
    RoomID           string `json:"room_id"`
    RoomType         string `json:"room_type,omitempty"`
    Topic            string `json:"topic,omitempty"`
    WorldReadable    bool   `json:"world_readable"`
}

type PublicRoomsResponse struct {
    Chunk                  []PublishedRoomsChunk `json:"chunk"`
    NextBatch              string                `json:"next_batch,omitempty"`
    PrevBatch              string                `json:"prev_batch,omitempty"`
    TotalRoomCountEstimate *int                  `json:"total_room_count_estimate,omitempty"`
}

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

// - make_join --

type MembershipContent struct {
    JoinAuthorisedViaUsersServer string `json:"join_authorised_via_users_server,omitempty"`
    Membership                   string `json:"membership"`
}

// EventTemplate é o template de evento unsigned retornado pelo make_join.
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

// -- send_join --

// SendJoinRequest é o PDU assinado enviado pelo servidor remoto
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

// StatePDU representa um evento de estado no formato Matrix para a resposta do send_join
type StatePDU struct {
    EventID        string            `json:"event_id"`
    Type           string            `json:"type"`
    RoomID         string            `json:"room_id"`
    Sender         string            `json:"sender"`
    StateKey       string            `json:"state_key"`
    OriginServerTS int64             `json:"origin_server_ts"`
    Content        json.RawMessage   `json:"content"`
}

type SendJoinResponse struct {
    AuthChain      []StatePDU `json:"auth_chain"`
    State          []StatePDU `json:"state"`
    MembersOmitted bool       `json:"members_omitted,omitempty"`
    ServersInRoom  []string   `json:"servers_in_room,omitempty"`
}