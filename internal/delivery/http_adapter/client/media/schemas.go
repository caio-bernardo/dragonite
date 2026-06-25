package media

// UploadResponse é o corpo da resposta 200 para um upload bem-sucedido.
// Ref: https://spec.matrix.org/v1.18/client-server-api/#post_matrixmediav3upload
type UploadResponse struct {
	ContentURI string `json:"content_uri"` // MXC URI: mxc://<server>/<media_id>
}