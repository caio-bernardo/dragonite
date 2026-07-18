CREATE TABLE IF NOT EXISTS VersaoBackup (
    id_versao BIGSERIAL PRIMARY KEY,
    id_usuario VARCHAR(512) NOT NULL REFERENCES Usuario(id_usuario) ON DELETE CASCADE,
    algorithm VARCHAR(255) NOT NULL,
    auth_data JSONB NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    etag VARCHAR(255) NOT NULL DEFAULT '0',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_versaobackup_usuario ON VersaoBackup (id_usuario, id_versao DESC);

CREATE TABLE IF NOT EXISTS ChaveBackup (
    id_versao BIGINT NOT NULL REFERENCES VersaoBackup(id_versao) ON DELETE CASCADE,
    id_canal VARCHAR(255) NOT NULL,
    id_sessao VARCHAR(255) NOT NULL,
    first_message_index BIGINT NOT NULL,
    forwarded_count BIGINT NOT NULL DEFAULT 0,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    session_data JSONB NOT NULL,
    PRIMARY KEY (id_versao, id_canal, id_sessao)
);

CREATE TABLE IF NOT EXISTS Chave_Dispositivo (
    fk_id_dispositivo UUID PRIMARY KEY REFERENCES Dispositivo(id) ON DELETE CASCADE,
    algorithms TEXT[] NOT NULL,
    device_keys JSONB NOT NULL,
    signatures JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Chave_Uso_Unico (
    id BIGSERIAL PRIMARY KEY,
    fk_id_dispositivo UUID NOT NULL REFERENCES Dispositivo(id) ON DELETE CASCADE,
    key_id VARCHAR(255) NOT NULL,
    algorithm VARCHAR(255) NOT NULL,
    key_data JSONB NOT NULL,
    UNIQUE (fk_id_dispositivo, key_id)
);

CREATE INDEX IF NOT EXISTS idx_chave_uso_unico_dispositivo_algoritmo ON Chave_Uso_Unico (fk_id_dispositivo, algorithm);

CREATE TABLE IF NOT EXISTS Chave_Fallback (
    fk_id_dispositivo UUID NOT NULL REFERENCES Dispositivo(id) ON DELETE CASCADE,
    algorithm VARCHAR(255) NOT NULL,
    key_id VARCHAR(255) NOT NULL,
    key_data JSONB NOT NULL,
    usada BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (fk_id_dispositivo, algorithm)
);

CREATE TABLE IF NOT EXISTS Chave_Cross_Signing (
    fk_id_usuario VARCHAR(512) NOT NULL REFERENCES Usuario(id_usuario) ON DELETE CASCADE,
    key_usage VARCHAR(20) NOT NULL CHECK (key_usage IN ('master', 'self_signing', 'user_signing')),
    key_id VARCHAR(255) NOT NULL, -- chave pública "crua", sem prefixo de algoritmo 
    public_key JSONB NOT NULL,    -- objeto {"ed25519:<pubkey>": "<pubkey>"}, igual à spec
    signatures JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (fk_id_usuario, key_usage)
);

CREATE INDEX IF NOT EXISTS idx_chave_cross_signing_key_id ON Chave_Cross_Signing (key_id);