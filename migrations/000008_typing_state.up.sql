CREATE TABLE IF NOT EXISTS typing_state (
    room_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    is_typing BOOLEAN NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (room_id, user_id)
);
