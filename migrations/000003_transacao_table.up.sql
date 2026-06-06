
CREATE TABLE IF NOT EXISTS transaction_id_cache (
    access_token_id VARCHAR(255) NOT NULL, -- Ties it to the specific device session
    txn_id VARCHAR(255) NOT NULL,          -- The ID the client sent
    endpoint VARCHAR(255) NOT NULL,        -- e.g., '/_matrix/client/v3/rooms/.../send'
    event_id VARCHAR(255) NOT NULL,        -- The hash we generated for the payload
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (access_token_id, txn_id, endpoint)
);

-- Index to clean up old transactions
CREATE INDEX IF NOT EXISTS idx_txn_cache_created_at ON transaction_id_cache(created_at);
