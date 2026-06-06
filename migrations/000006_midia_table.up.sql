CREATE TABLE IF NOT EXISTS Midia (
    id_midia VARCHAR(255) NOT NULL,
    origin VARCHAR(255) NOT NULL,
    content_type VARCHAR(255) NOT NULL,
    size_bytes BIGINT NOT NULL,
    upload_name VARCHAR(255),
    id_usuario VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (origin, id_midia)
);
