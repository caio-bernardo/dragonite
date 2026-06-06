
-- 1. Filters Table
CREATE TABLE IF NOT EXISTS user_filters (
    filter_id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    filter_data JSONB NOT NULL -- The actual JSON rules
);

-- 2. Read Receipts Table
CREATE TABLE IF NOT EXISTS read_receipts (
    room_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    event_id VARCHAR(255) NOT NULL,
    ts BIGINT NOT NULL,

    -- A user only has ONE active read receipt per room
    PRIMARY KEY (room_id, user_id)
);
