package federation

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