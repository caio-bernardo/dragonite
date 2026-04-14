package model

type UsuarioCanal struct {
	ID        string `json:"id"`
	UsuarioID string `json:"usuario_id"`
	CanalID   string `json:"canal_id"`
	DataHora  int    `json:"data_hora"`
}

type UsuarioCanalCreate struct {
	UsuarioID string `json:"usuario_id"`
	CanalID   string `json:"canal_id"`
}

func (ucc UsuarioCanalCreate) ToUsuarioCanal() UsuarioCanal {
	return UsuarioCanal{
		UsuarioID: ucc.UsuarioID,
		CanalID:   ucc.CanalID,
	}
}
