package rooms

// GET /publicRooms 

// PublicRoomChunk representa uma entrada na listagem de salas públicas.
// Ref: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv3publicrooms
type PublicRoomChunk struct {
	RoomID           string  `json:"room_id"`
	Name             *string `json:"name,omitempty"`
	Topic            *string `json:"topic,omitempty"`
	AvatarURL        *string `json:"avatar_url,omitempty"`
	CanonicalAlias   *string `json:"canonical_alias,omitempty"`
	NumJoinedMembers int     `json:"num_joined_members"`
	WorldReadable    bool    `json:"world_readable"`
	GuestCanJoin     bool    `json:"guest_can_join"`
	JoinRule         *string `json:"join_rule,omitempty"`
}

// PublicRoomsResponse é o corpo de resposta de GET /publicRooms.
type PublicRoomsResponse struct {
	Chunk                  []PublicRoomChunk `json:"chunk"`
	NextBatch              *string           `json:"next_batch,omitempty"`
	PrevBatch              *string           `json:"prev_batch,omitempty"`
	TotalRoomCountEstimate *int              `json:"total_room_count_estimate,omitempty"`
}

// POST /createRoom 

// InitialStateEvent representa um evento de estado a ser inserido na criação.
// Ref: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3createroom
type InitialStateEvent struct {
	Type     string         `json:"type"`
	StateKey string         `json:"state_key"`
	Content  map[string]any `json:"content"`
}

// CreateRoomRequest é o corpo de requisição de POST /createRoom.
type CreateRoomRequest struct {
	Visibility    string              `json:"visibility"`        // "public" | "private"
	RoomAliasName *string             `json:"room_alias_name"`   // sem '#' e sem ':server'
	Name          *string             `json:"name,omitempty"`
	Topic         *string             `json:"topic,omitempty"`
	Invite        []string            `json:"invite,omitempty"`
	InitialState  []InitialStateEvent `json:"initial_state,omitempty"`
	Preset        *string             `json:"preset,omitempty"` // "private_chat" | "trusted_private_chat" | "public_chat"
	IsDirect      bool                `json:"is_direct,omitempty"`
	RoomVersion   *string             `json:"room_version,omitempty"`
}

// CreateRoomResponse é o corpo de resposta de POST /createRoom.
type CreateRoomResponse struct {
	RoomID string `json:"room_id"`
}

//  POST /rooms/{roomId}/join 

// JoinRoomRequest é o corpo de requisição de POST /rooms/{roomId}/join.
// O spec permite body vazio, então todos os campos são opcionais
// Ref: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidjoin
type JoinRoomRequest struct {
	Reason *string `json:"reason,omitempty"`
}

// JoinRoomResponse é o corpo de resposta de POST /rooms/{roomId}/join.
type JoinRoomResponse struct {
	RoomID string `json:"room_id"`
}

// POST /rooms/{roomId}/leave

// LeaveRoomRequest é o corpo de requisição de POST /rooms/{roomId}/leave.
// Ref: https://spec.matrix.org/v1.18/client-server-api/#post_matrixclientv3roomsroomidleave
type LeaveRoomRequest struct {
	Reason *string `json:"reason,omitempty"`
}
// Resposta de leave é {} com 200 OK, então não precisa de struct dedicada

// PUT /rooms/{roomId}/send/{eventType}/{txnId}

// Ref: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid
type SendEventRequest map[string]any

// Resposta de PUT /rooms/{roomId}/send/{eventType}/{txnId}
type SendEventResponse struct {
	EventID string `json:"event_id"`
}

// PUT /rooms/{roomId}/state/{eventType}/{stateKey}

// Ref: https://spec.matrix.org/v1.18/client-server-api/#put_matrixclientv3roomsroomidstateeventtypestateke
type StateEventRequest map[string]any

// Resposta de PUT /rooms/{roomId}/state/{eventType}/{stateKey}
type StateEventResponse struct {
	EventID string `json:"event_id"`
}