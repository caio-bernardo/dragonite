package usecase

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
)

// DefaultMaxUploadBytes define o limite padrão de 50 MB por upload
const DefaultMaxUploadBytes int64 = 50 * 1024 * 1024

// ErrMediaTooLarge é retornado quando o arquivo excede o tamanho máximo permitido
var ErrMediaTooLarge = errors.New("the file exceeds the maximum allowed size")

// ErrMediaNotFound é retornado quando a mídia solicitada não existe, nem localmente
var ErrMediaNotFound = errors.New("media not found")

// MediaService contém a lógica de negócio para upload de arquivos de mídia.
// Coordena o armazenamento do arquivo (MinIO via FileStorage) e dos metadados (Postgres via MidiaStorage)
type MediaService struct {
	serverName    string
	fileStorage   FileStorage
	midiaStorage  MidiaStorage
	maxSizeBytes  int64
	remoteFetcher RemoteMediaFetcher
}

// NewMediaService cria uma nova instância do MediaService.
// Se maxSizeBytes for <= 0, usa DefaultMaxUploadBytes (50 MB)
func NewMediaService(
	serverName string,
	fileStorage FileStorage,
	midiaStorage MidiaStorage,
	maxSizeBytes int64,
	remoteFetcher RemoteMediaFetcher,
) *MediaService {
	if maxSizeBytes <= 0 {
		maxSizeBytes = DefaultMaxUploadBytes
	}

	return &MediaService{
		serverName:    serverName,
		fileStorage:   fileStorage,
		midiaStorage:  midiaStorage,
		maxSizeBytes:  maxSizeBytes,
		remoteFetcher: remoteFetcher,
	}
}

// UploadParams contém os dados necessários para realizar um upload de mídia.
type UploadParams struct {
	Content     io.Reader // Corpo da requisição HTTP
	ContentType string    // Header Content-Type (default: application/octet-stream)
	UploadName  string    // Query param ?filename=
	UploaderID  string    // userID injetado pelo middleware de autenticação
	Size        int64     // Content-Length do header (-1 se não enviado pelo cliente)
}

// UploadResult contém o resultado de um upload bem-sucedido.
type UploadResult struct {
	ContentURI string // MXC URI no formato mxc://<server>/<media_id>
}

// MaxUploadSize retorna o limite máximo de upload configurado, em bytes.
// Usado por GET /_matrix/client/v1/media/config para informar o cliente
func (s *MediaService) MaxUploadSize() int64 {
	return s.maxSizeBytes
}

// Upload valida, armazena e registra um arquivo de mídia.
func (s *MediaService) Upload(ctx context.Context, params UploadParams) (*UploadResult, error) {
	// Rejeição rápida se Content-Length já é conhecido e excede o limite
	if params.Size > 0 && params.Size > s.maxSizeBytes {
		return nil, ErrMediaTooLarge
	}

	if params.ContentType == "" {
		params.ContentType = "application/octet-stream"
	}

	// Lê o body em memória aplicando limite de segurança.
	// Tentamos ler maxSizeBytes+1 bytes: se conseguirmos, o arquivo é grande demais
	// Isso protege contra clientes que omitem o Content-Length
	limitedReader := io.LimitReader(params.Content, s.maxSizeBytes+1)
	buf, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %w", err)
	}
	if int64(len(buf)) > s.maxSizeBytes {
		return nil, ErrMediaTooLarge
	}

	actualSize := int64(len(buf))

	mediaID, err := generateMediaID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate media ID: %w", err)
	}

	// Upload para o MinIO com tamanho exato (mais eficiente que -1/streaming)
	if err := s.fileStorage.Upload(ctx, mediaID, bytes.NewReader(buf), actualSize, params.ContentType); err != nil {
		return nil, fmt.Errorf("failure to store file in object storage: %w", err)
	}

	// 4. Persiste os metadados no banco
	midia := &domain.Midia{
		IDMidia:     mediaID,
		Origin:      s.serverName,
		ContentType: params.ContentType,
		SizeBytes:   actualSize,
		UploadName:  params.UploadName,
		IDUsuario:   params.UploaderID,
		CreatedAt:   time.Now().UTC(),
	}

	if err := s.midiaStorage.SaveMidia(ctx, midia); err != nil {
		// Limpeza: remove o arquivo do MinIO para não deixar objetos órfãos
		_ = s.fileStorage.Delete(ctx, mediaID)
		return nil, fmt.Errorf("failure to save media metadata: %w", err)
	}

	contentURI := fmt.Sprintf("mxc://%s/%s", s.serverName, mediaID)
	return &UploadResult{ContentURI: contentURI}, nil
}

// generateMediaID gera um identificador único de 16 bytes representado em hexadecimal (32 chars).
func generateMediaID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failure to generate random bytes: %w", err)
	}

	return hex.EncodeToString(b), nil
}

// DownloadResult contém o conteúdo e os metadados necessários para servir uma resposta
// GET /_matrix/client/v1/media/download ou .../thumbnail
// Content deve SEMPRE ser fechado pelo chamador (defer result.Content.Close())
type DownloadResult struct {
	Content     io.ReadCloser
	ContentType string
	Filename    string
}

// Download recupera um arquivo de mídia identificado por (serverName, mediaID)
// Dois caminhos possíveis:
//   - serverName é o nosso próprio servidor: busca os metadados no Postgres e o binário no MinIO
//   - serverName é de outro servidor: repassa a busca via federação (remoteFetcher), fazendo
//     proxy do arquivo sem nunca armazená-lo localmente
func (s *MediaService) Download(ctx context.Context, serverName, mediaID string) (*DownloadResult, error) {
	if serverName == s.serverName {
		return s.downloadLocal(ctx, mediaID)
	}
	return s.downloadRemote(ctx, serverName, mediaID)
}

// Thumbnail atualmente reaproveita Download por completo: este servidor não gera miniaturas
// redimensionadas de verdade, em vez disso devolvemos o arquivo original e clientes como o Element
// toleram bem receber a imagem original no lugar de uma miniatura, redimensionando-a localmente
func (s *MediaService) Thumbnail(ctx context.Context, serverName, mediaID string) (*DownloadResult, error) {
	return s.Download(ctx, serverName, mediaID)
}

// downloadLocal busca metadados no Postgres e o binário no MinIO para mídia hospedada neste servidor
func (s *MediaService) downloadLocal(ctx context.Context, mediaID string) (*DownloadResult, error) {
	midia, err := s.midiaStorage.GetMidiaByID(ctx, s.serverName, mediaID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch media metadata: %w", err)
	}
	if midia == nil {
		return nil, ErrMediaNotFound
	}

	content, err := s.fileStorage.Download(ctx, mediaID)
	if err != nil {
		return nil, fmt.Errorf("failed to download file from object storage: %w", err)
	}

	return &DownloadResult{
		Content:     content,
		ContentType: midia.ContentType,
		Filename:    midia.UploadName,
	}, nil
}

// DownloadLocal busca uma mídia hospedada neste servidor, sem decidir entre local/remoto
func (s *MediaService) DownloadLocal(ctx context.Context, mediaID string) (*DownloadResult, error) {
	return s.downloadLocal(ctx, mediaID)
}

// downloadRemote faz proxy da mídia hospedada em outro servidor via federação
func (s *MediaService) downloadRemote(ctx context.Context, serverName, mediaID string) (*DownloadResult, error) {
	if s.remoteFetcher == nil {
		return nil, ErrMediaNotFound
	}

	content, contentType, filename, err := s.remoteFetcher.FetchRemoteMedia(ctx, serverName, mediaID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch remote media from %s: %w", serverName, err)
	}

	return &DownloadResult{
		Content:     content,
		ContentType: contentType,
		Filename:    filename,
	}, nil
}
