CREATE TABLE IF NOT EXISTS Dispositivo (
    id_dispositivo varchar(50) PRIMARY KEY,
    nome_dispositivo varchar(50) NOT NULL,
    ultimo_ip_visto varchar(50),
    ultimo_timestamp_visto varchar(50)
);
