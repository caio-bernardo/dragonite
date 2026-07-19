CREATE TABLE IF NOT EXISTS Mensagem_ToDevice (
    id BIGSERIAL PRIMARY KEY,
    fk_id_usuario VARCHAR(512) NOT NULL REFERENCES Usuario(id_usuario) ON DELETE CASCADE,
    fk_id_dispositivo UUID NOT NULL REFERENCES Dispositivo(id) ON DELETE CASCADE,
    remetente VARCHAR(512) NOT NULL, -- Matrix user ID de quem enviou; sem FK pois pode ser remoto
    tipo VARCHAR(255) NOT NULL,
    content JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mensagem_todevice_destino ON Mensagem_ToDevice (fk_id_usuario, fk_id_dispositivo, id);