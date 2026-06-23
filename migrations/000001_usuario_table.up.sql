CREATE DOMAIN USUARIO_LOCALPART_T AS VARCHAR(255) CHECK (
    VALUE ~ '^[\w\d._=+-]+$'
);

CREATE TABLE IF NOT EXISTS Usuario (
    id_usuario VARCHAR(512) PRIMARY KEY,
    localpart USUARIO_LOCALPART_T UNIQUE NOT NULL,
    senha_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Profile (
    fk_usuario_id VARCHAR(512) REFERENCES Usuario(id_usuario),
    nome VARCHAR(255) NOT NULL,
    foto_url VARCHAR(255),
    PRIMARY KEY (fk_usuario_id)
);

CREATE TABLE IF NOT EXISTS AccountData (
    fk_id_usuario VARCHAR(512) NOT NULL REFERENCES Usuario(id_usuario) ON DELETE CASCADE,
    id_canal VARCHAR(255) DEFAULT '',
    tipo VARCHAR(255) NOT NULL,
    content JSONB NOT NULL,
    PRIMARY KEY (fk_id_usuario, id_canal, tipo)
);

CREATE TABLE IF NOT EXISTS Dispositivo (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    fk_id_usuario varchar(255) NOT NULL REFERENCES Usuario(id_usuario) ON DELETE CASCADE,
    nome varchar(255),
    refresh_token varchar(64) NOT NULL UNIQUE, -- token de "refresco" do token de acesso
    refresh_token_expires_at TIMESTAMP WITH TIME ZONE,
    ultimo_ip_visto varchar(50),
    ultimo_timestamp_visto TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_dispositivo_refresh_token ON Dispositivo (refresh_token);
CREATE INDEX IF NOT EXISTS idx_dispositivo_ultimo_ts_visto ON Dispositivo (ultimo_timestamp_visto);
