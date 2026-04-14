CREATE TABLE IF NOT EXISTS Mensagem (
    id_mensagem varchar(50) PRIMARY KEY,
    nome_dispositivo varchar(50) NOT NULL,
    texto_mensagem text,
    data_hora integer,
    autor varchar(50)
);
