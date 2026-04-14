package model

type Dispositivo struct {
	ID                   string `json:"id_dispositivo"`
	Nome                 string `json:"nome_dispositivo"`
	UltimoIPVisto        string `json:"ultimo_ip_visto"`
	UltimoTimestampVisto string `json:"ultimo_timestamp_visto"`
}

type DispositivoCreate struct {
	Nome                 string `json:"nome_dispositivo"`
	UltimoIPVisto        string `json:"ultimo_ip_visto"`
	UltimoTimestampVisto string `json:"ultimo_timestamp_visto"`
}

func (dr DispositivoCreate) ToDispositivo() Dispositivo {
	return Dispositivo{
		Nome:                 dr.Nome,
		UltimoIPVisto:        dr.UltimoIPVisto,
		UltimoTimestampVisto: dr.UltimoTimestampVisto,
	}
}
