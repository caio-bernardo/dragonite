package media

// UploadResponse é o corpo da resposta 200 para um upload bem-sucedido.
type UploadResponse struct {
	ContentURI string `json:"content_uri"` // MXC URI: mxc://<server>/<media_id>
}

// MediaConfigResponse é o corpo da resposta 200 para GET /_matrix/client/v1/media/config
type MediaConfigResponse struct {
	// MUploadSize é o tamanho máximo de upload em bytes. Ponteiro para permitir omissão
	// via omitempty caso, no futuro, o limite seja desconhecido/desabilitado
	MUploadSize *int64 `json:"m.upload.size,omitempty"`
}
