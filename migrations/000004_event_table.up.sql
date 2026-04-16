CREATE TABLE IF NOT EXISTS Evento (
    id_evento VARCHAR(512) PRIMARY KEY, -- $id:dominio.com
    tipo_evento VARCHAR(255) NOT NULL, -- m.room.message ou m.room.member
    fk_id_canal VARCHAR(512) NOT NULL REFERENCES canal(id_canal),
    fk_id_sender VARCHAR(512) NOT NULL REFERENCES usuario(id_usuario),
    state_key VARCHAR(255), -- para eventos que mudam o estado do canal
    conteudo_evento JSONB NOT NULL,
    origem_servidor_evento_ts BIGINT NOT NULL, -- timestamp em milissegundos (requerido pelo matrix)
    stream_ordering_evento BIGSERIAL UNIQUE NOT NULL -- contador global para os eventos
);

CREATE INDEX IF NOT EXISTS idx_evento_canal_stream ON Evento(fk_id_canal, stream_ordering_evento);
CREATE INDEX IF NOT EXISTS idx_evento_tipo ON Evento(tipo_evento);
CREATE INDEX IF NOT EXISTS idx_evento_state ON Evento(fk_id_canal, tipo_evento, state_key) WHERE state_key IS NOT NULL;

-- Relaciona um evento ao seus antecessores, formando uma linha do tempo
CREATE TABLE IF NOT EXISTS Aresta_Evento (
    fk_id_evento VARCHAR(512) NOT NULL REFERENCES Evento(id_evento) ON DELETE CASCADE,
    id_evento_antecessor VARCHAR(512) NOT NULL,
    fk_id_canal VARCHAR(512) NOT NULL REFERENCES canal(id_canal),
    is_state BOOLEAN DEFAULT FALSE, -- aresta define estado/fluxo na linha do tempo
    PRIMARY KEY (fk_id_evento, id_evento_antecessor)
);

CREATE INDEX IF NOT EXISTS idx_evento_aresta_antecessor ON Aresta_Evento(id_evento_antecessor);
