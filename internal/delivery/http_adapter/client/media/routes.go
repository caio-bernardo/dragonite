package media

import (
	"errors"
	"log"
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/delivery/http_adapter/httputil"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

// Handler agrupa as rotas de mídia do cliente Matrix.
type Handler struct {
	mediaService *usecase.MediaService
}

// NewHandler cria um Handler de mídia com o serviço injetado.
func NewHandler(mediaService *usecase.MediaService) *Handler {
	return &Handler{mediaService: mediaService}
}

// RegisterRoutes registra as rotas de mídia no mux.
// Todas as rotas de mídia exigem autenticação.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware httputil.Middleware) {
	// TODO: adicionar rate limiting por userID antes do authMiddleware quando
	// a infraestrutura de rate limiting for implementada no projeto.
	mux.Handle("POST /_matrix/media/v3/upload", authMiddleware(http.HandlerFunc(h.uploadMedia)))
}

// uploadMedia recebe e armazena um arquivo de mídia enviado pelo cliente.
// POST /_matrix/media/v3/upload
// Ref: https://spec.matrix.org/v1.18/client-server-api/#post_matrixmediav3upload
func (h *Handler) uploadMedia(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(types.UserIDKey).(string)
	if !ok || userID == "" {
		httputil.WriteMatrixError(w, http.StatusUnauthorized, httputil.M_MISSING_TOKEN, "Missing or invalid auth token")
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	filename := r.URL.Query().Get("filename")

	result, err := h.mediaService.Upload(r.Context(), usecase.UploadParams{
		Content:     r.Body,
		ContentType: contentType,
		UploadName:  filename,
		UploaderID:  userID,
		Size:        r.ContentLength, // -1 se o cliente não enviou Content-Length
	})
	if err != nil {
		if errors.Is(err, usecase.ErrMediaTooLarge) {
			httputil.WriteMatrixError(
				w,
				http.StatusRequestEntityTooLarge,
				httputil.M_TOO_LARGE,
				"The file exceeds the maximum size allowed by the server.",
			)
			return
		}

		log.Printf("[ERROR] POST /_matrix/media/v3/upload (user=%s): %v", userID, err)
		httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to process upload.")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, UploadResponse{
		ContentURI: result.ContentURI,
	})
}
