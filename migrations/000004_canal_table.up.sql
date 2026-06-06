CREATE TABLE IF NOT EXISTS Canal (
    id_canal VARCHAR(255) PRIMARY KEY,
    versao_canal VARCHAR(50) NOT NULL DEFAULT '11',
    criador VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Canal_Alias (
    id_canal VARCHAR(255) NOT NULL,
    alias VARCHAR(255) NOT NULL,
    id_evento VARCHAR(255) NOT NULL,

    PRIMARY KEY (id_canal, alias)
);

CREATE TABLE IF NOT EXISTS Canal_Extremidades (
    id_canal VARCHAR(255) NOT NULL REFERENCES Canal(id_canal),
    id_evento VARCHAR(255) NOT NULL REFERENCES Evento(id_evento),

    PRIMARY KEY (id_canal, id_evento)
);

CREATE TABLE IF NOT EXISTS Canal_Estado_Atual (
    id_canal VARCHAR(255) NOT NULL REFERENCES Canal(id_canal),
    tipo VARCHAR(255) NOT NULL,
    state_key VARCHAR(255) NOT NULL,
    id_evento VARCHAR(255) NOT NULL REFERENCES Evento(id_evento),

    PRIMARY KEY (id_canal, tipo, state_key)
);

CREATE TABLE IF NOT EXISTS Canal_Membership (
    id_canal VARCHAR(255) NOT NULL,
    id_usuario VARCHAR(255) NOT NULL,
    membership_type VARCHAR(50) NOT NULL, -- join, leave, invite
    id_evento VARCHAR(255) NOT NULL REFERENCES Evento(id_evento),

    PRIMARY KEY (id_canal, id_usuario)
);

CREATE INDEX IF NOT EXISTS idx_canal_membership_usuario ON Canal_Membership(id_usuario, membership_type);
