package model

type Usuario struct {
	ID          string `json:"id_usuario"`
	Nome        string `json:"nome_usuario"`
	Email       string `json:"email_usuario"`
	Senha       string `json:"senha_usuario"`
	Token       string `json:"token_usuario"`
	Foto        string `json:"foto_usuario"`
	Host        string `json:"host_usuario"`
	DataCriacao int    `json:"data_criacao_usuario"`
}

type UsuarioCreate struct {
	Nome        string `json:"nome_usuario"`
	Email       string `json:"email_usuario"`
	Senha       string `json:"senha_usuario"`
	Foto        string `json:"foto_usuario"`
	Host        string `json:"host_usuario"`
	DataCriacao int    `json:"data_criacao_usuario"`
}

func (uc UsuarioCreate) ToUsuario() Usuario {
	return Usuario{
		Nome:        uc.Nome,
		Email:       uc.Email,
		Senha:       uc.Senha,
		Foto:        uc.Foto,
		Host:        uc.Host,
		DataCriacao: uc.DataCriacao,
	}
}
