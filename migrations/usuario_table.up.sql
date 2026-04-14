CREATE TABLE IF NOT EXISTS Usuario (
    id_usuario varchar(50) PRIMARY KEY,
    nome_usuario varchar(50) NOT NULL,
    email_usuario varchar(50) NOT NULL,
    senha_usuario varchar(50) NOT NULL,
    token_usuario varchar(50),
    foto_usuario varchar(50),
    host_usuario varchar(50),
    data_criacao_usuario integer
);
