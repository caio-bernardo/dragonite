package model

type Mensagem struct {
	ID       string `json:"id_mensagem"`
	Texto    string `json:"texto_mensagem"`
	DataHora int    `json:"data_hora"`
	Autor    string `json:"autor"`
}

type MensagemCreate struct {
	Texto string `json:"texto_mensagem"`
	Autor string `json:"autor"`
}

func (ms MensagemCreate) ToMensagem() Mensagem {
	return Mensagem{
		Texto: ms.Texto,
		Autor: ms.Autor,
	}
}
