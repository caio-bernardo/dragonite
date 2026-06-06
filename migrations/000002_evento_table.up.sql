CREATE TABLE IF NOT EXISTS Evento (
    id_evento VARCHAR(255) PRIMARY KEY,
    tipo VARCHAR(255) NOT NULL,
    id_canal VARCHAR(255) NOT NULL,
    sender VARCHAR(255) NOT NULL,
    origin_server_ts BIGINT NOT NULL,
    content JSONB NOT NULL,

    stream_ordering BIGSERIAL NOT NULL,

    state_key VARCHAR(255),          -- Nullable. If not null, it's a state event
    redacts VARCHAR(255),            -- Nullable.

    prev_eventos TEXT[] NOT NULL,     -- The edges of our DAG
    auth_eventos TEXT[] NOT NULL,
    depth BIGINT NOT NULL,

    hashes JSONB,
    signatures JSONB
);

CREATE INDEX IF NOT EXISTS idx_events_stream_ordering ON Evento(stream_ordering); -- ordenar eventos para o /sync
CREATE INDEX IF NOT EXISTS idx_events_room_id ON Evento(id_canal);
CREATE INDEX IF NOT EXISTS idx_events_room_state ON Evento(id_canal, tipo, state_key) WHERE state_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS Aresta_Evento (
    id_canal VARCHAR(255) NOT NULL,
    id_evento VARCHAR(255) NOT NULL,       -- The newer event
    prev_evento_id VARCHAR(255) NOT NULL,  -- The older event it points to
    is_state BOOLEAN DEFAULT FALSE,       -- Optimization: Is the older event a state event?

    PRIMARY KEY (id_canal, prev_evento_id),

    -- Ensure we don't have orphaned edges
    CONSTRAINT fk_id_evento FOREIGN KEY (id_evento) REFERENCES Evento(id_evento) ON DELETE CASCADE
);

-- CRITICAL: This index allows us to traverse the DAG forwards instantly.
-- It answers: "Who points to prev_event_id?"
CREATE INDEX IF NOT EXISTS idx_event_edges_prev_event_id ON Aresta_Evento(prev_evento_id);

-- Useful for calculating room depth and resolving state
CREATE INDEX IF NOT EXISTS idx_event_edges_room_id ON Aresta_Evento(id_canal);
