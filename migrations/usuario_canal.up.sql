CREATE TABLE IF NOT EXISTS UsuarioCanal (
    id varchar(50) PRIMARY KEY,
    usuario_id varchar(50) NOT NULL,
    canal_id varchar(50) NOT NULL,
    data_hora integer
);
