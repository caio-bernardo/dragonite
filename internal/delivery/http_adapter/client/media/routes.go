package media

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

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
	mux.Handle("GET /_matrix/client/v1/media/download/{serverName}/{mediaId}", authMiddleware(http.HandlerFunc(h.downloadMedia)))
	mux.Handle("GET /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}", authMiddleware(http.HandlerFunc(h.thumbnailMedia)))
	mux.Handle("GET /_matrix/client/v1/media/config", authMiddleware(http.HandlerFunc(h.mediaConfig)))
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

// downloadMedia serve o conteúdo de um arquivo de mídia identificado por serverName/mediaId
// GET /_matrix/client/v1/media/download/{serverName}/{mediaId}
// Ref: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1mediadownloadservernamemediaid
//
// Se serverName for este servidor, busca localmente (Postgres + MinIO). Caso contrário, faz
// proxy da mídia via federação (ver FederationService.FetchRemoteMedia), o arquivo nunca é
// persistido localmente, só repassado.
func (h *Handler) downloadMedia(w http.ResponseWriter, r *http.Request) {
	serverName := r.PathValue("serverName")
	mediaID := r.PathValue("mediaId")
	if serverName == "" || mediaID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing serverName or mediaId in path")
		return
	}
 
	result, err := h.mediaService.Download(r.Context(), serverName, mediaID)
	if err != nil {
		h.writeDownloadError(w, "download", serverName, mediaID, err)
		return
	}
	defer result.Content.Close()
 
	writeMediaResponse(w, result)
}
 
// thumbnailMedia devolve uma miniatura de um arquivo de mídia
// GET /_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}
// Ref: https://spec.matrix.org/v1.18/client-server-api/#get_matrixclientv1mediathumbnailservernamemediaid
func (h *Handler) thumbnailMedia(w http.ResponseWriter, r *http.Request) {
	serverName := r.PathValue("serverName")
	mediaID := r.PathValue("mediaId")
	if serverName == "" || mediaID == "" {
		httputil.WriteMatrixError(w, http.StatusBadRequest, httputil.M_BAD_JSON, "Missing serverName or mediaId in path")
		return
	}
 
	result, err := h.mediaService.Thumbnail(r.Context(), serverName, mediaID)
	if err != nil {
		h.writeDownloadError(w, "thumbnail", serverName, mediaID, err)
		return
	}
	defer result.Content.Close()
 
	writeMediaResponse(w, result)
}
 
// writeDownloadError centraliza o mapeamento de erros do MediaService para respostas Matrix,
// evitando duplicar a lógica entre downloadMedia e thumbnailMedia.
func (h *Handler) writeDownloadError(w http.ResponseWriter, op, serverName, mediaID string, err error) {
	if errors.Is(err, usecase.ErrMediaNotFound) {
		httputil.WriteMatrixError(w, http.StatusNotFound, httputil.M_NOT_FOUND, "Media not found")
		return
	}
 
	log.Printf("[ERROR] GET /_matrix/client/v1/media/%s/%s/%s: %v", op, serverName, mediaID, err)
	httputil.WriteMatrixError(w, http.StatusInternalServerError, httputil.M_UNKNOWN, "Failed to retrieve media")
}
 
// writeMediaResponse escreve os bytes crus do arquivo com os headers exigidos pela spec Matrix
// (Content-Type e Content-Disposition), fazendo streaming direto para o cliente sem carregar tudo em memória.
func writeMediaResponse(w http.ResponseWriter, result *usecase.DownloadResult) {
	disposition := "attachment"
	if isInlineSafe(result.ContentType) {
		disposition = "inline"
	}
	if result.Filename != "" {
		disposition = fmt.Sprintf(`%s; filename="%s"`, disposition, result.Filename)
	}
 
	w.Header().Set("Content-Type", result.ContentType)
	w.Header().Set("Content-Disposition", disposition)
	w.WriteHeader(http.StatusOK)
 
	if _, err := io.Copy(w, result.Content); err != nil {
		log.Printf("[ERROR] failed to stream media response: %v", err)
	}
}
 
// isInlineSafe retorna true para tipos de conteúdo seguros para exibição inline no navegador
func isInlineSafe(contentType string) bool {
	for _, prefix := range []string{"image/", "audio/", "video/", "text/"} {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}

// mediaConfig retorna a configuração pública do repositório de conteúdo do servidor
// GET /_matrix/client/v1/media/config
func (h *Handler) mediaConfig(w http.ResponseWriter, r *http.Request) {
	maxSize := h.mediaService.MaxUploadSize()

	httputil.WriteJSON(w, http.StatusOK, MediaConfigResponse{
		MUploadSize: &maxSize,
	})
}