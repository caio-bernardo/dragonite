package model

type Canal struct {
	ID        string `json:"id_canal"`
	Nome      string `json:"nome_canal"`
	Descricao string `json:"descricao_canal"`
	Foto      string `json:"foto_canal"`
}

type CanalCreate struct {
	Nome      string `json:"nome_canal"`
	Descricao string `json:"descricao_canal"`
	Foto      string `json:"foto_canal"`
}

func (c CanalCreate) ToCanal() Canal {
	return Canal{
		Nome:      c.Nome,
		Descricao: c.Descricao,
		Foto:      c.Foto,
	}
}
