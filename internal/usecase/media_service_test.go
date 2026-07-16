package usecase

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/domain"
)

// Fakes

type fakeFileStorage struct {
	uploadErr    error
	deleteErr    error
	deleteCalled bool
}

func (f *fakeFileStorage) Upload(_ context.Context, _ string, _ io.Reader, _ int64, _ string) error {
	return f.uploadErr
}

func (f *fakeFileStorage) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (f *fakeFileStorage) Delete(_ context.Context, _ string) error {
	f.deleteCalled = true
	return f.deleteErr
}

type fakeMidiaStorage struct {
	saveErr    error
	savedMidia *domain.Midia
	getResult  *domain.Midia 
	getErr     error
}

func (f *fakeMidiaStorage) SaveMidia(_ context.Context, midia *domain.Midia) error {
	f.savedMidia = midia
	return f.saveErr
}

func (f *fakeMidiaStorage) GetMidiaByID(_ context.Context, _, _ string) (*domain.Midia, error) {
	return f.getResult, f.getErr
}

// fakeRemoteFetcher simula o FederationService.FetchRemoteMedia sem nenhuma chamada de rede
type fakeRemoteFetcher struct {
	content     string
	contentType string
	filename    string
	err         error
	calledWith  struct {
		serverName string
		mediaID    string
	}
}
 
func (f *fakeRemoteFetcher) FetchRemoteMedia(_ context.Context, destServerName, mediaID string) (io.ReadCloser, string, string, error) {
	f.calledWith.serverName = destServerName
	f.calledWith.mediaID = mediaID
	if f.err != nil {
		return nil, "", "", f.err
	}
	return io.NopCloser(strings.NewReader(f.content)), f.contentType, f.filename, nil
}

// Testes de Upload

func TestMediaServiceUploadSuccess(t *testing.T) {
	fileStore := &fakeFileStorage{}
	midiaStore := &fakeMidiaStorage{}
	svc := NewMediaService("example.com", fileStore, midiaStore, 10*1024*1024, nil)

	result, err := svc.Upload(context.Background(), UploadParams{
		Content:     strings.NewReader("hello world"),
		ContentType: "text/plain",
		UploadName:  "hello.txt",
		UploaderID:  "@alice:example.com",
		Size:        11,
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if !strings.HasPrefix(result.ContentURI, "mxc://example.com/") {
		t.Fatalf("expected MXC URI with server name, got %s", result.ContentURI)
	}
	if midiaStore.savedMidia == nil {
		t.Fatal("expected metadata to be saved in DB")
	}
	if midiaStore.savedMidia.ContentType != "text/plain" {
		t.Fatalf("expected content_type 'text/plain', got %s", midiaStore.savedMidia.ContentType)
	}
	if midiaStore.savedMidia.IDUsuario != "@alice:example.com" {
		t.Fatalf("expected uploader '@alice:example.com', got %s", midiaStore.savedMidia.IDUsuario)
	}
	if midiaStore.savedMidia.UploadName != "hello.txt" {
		t.Fatalf("expected upload_name 'hello.txt', got %s", midiaStore.savedMidia.UploadName)
	}
}

func TestMediaServiceUploadDefaultContentType(t *testing.T) {
	// ContentType vazio deve ser preenchido com application/octet-stream
	midiaStore := &fakeMidiaStorage{}
	svc := NewMediaService("example.com", &fakeFileStorage{}, midiaStore, 0, nil)

	_, err := svc.Upload(context.Background(), UploadParams{
		Content:    strings.NewReader("data"),
		UploaderID: "@alice:example.com",
		Size:       4,
		// ContentType deliberadamente omitido
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if midiaStore.savedMidia == nil {
		t.Fatal("expected metadata to be saved")
	}
	if midiaStore.savedMidia.ContentType != "application/octet-stream" {
		t.Fatalf("expected default content type 'application/octet-stream', got %s", midiaStore.savedMidia.ContentType)
	}
}

func TestMediaServiceUploadTooLargeByContentLength(t *testing.T) {
	// Rejeição rápida pelo Content-Length antes mesmo de ler o corpo
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 100, nil)

	_, err := svc.Upload(context.Background(), UploadParams{
		Content:    strings.NewReader("x"),
		UploaderID: "@alice:example.com",
		Size:       999, // excede o limite de 100 bytes
	})

	if !errors.Is(err, ErrMediaTooLarge) {
		t.Fatalf("expected ErrMediaTooLarge, got %v", err)
	}
}

func TestMediaServiceUploadTooLargeByBody(t *testing.T) {
	// Detecta arquivo grande via LimitReader quando Content-Length não é enviado
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 5, nil)

	_, err := svc.Upload(context.Background(), UploadParams{
		Content:    strings.NewReader("123456789"), // 9 bytes > limite de 5
		UploaderID: "@alice:example.com",
		Size:       -1, // -1 = cliente não enviou Content-Length
	})

	if !errors.Is(err, ErrMediaTooLarge) {
		t.Fatalf("expected ErrMediaTooLarge, got %v", err)
	}
}

func TestMediaServiceUploadFileStorageError(t *testing.T) {
	// Falha no MinIO deve retornar erro sem tentar salvar no DB
	fileStore := &fakeFileStorage{uploadErr: errors.New("minio unavailable")}
	midiaStore := &fakeMidiaStorage{}
	svc := NewMediaService("example.com", fileStore, midiaStore, 0, nil)

	_, err := svc.Upload(context.Background(), UploadParams{
		Content:    strings.NewReader("data"),
		UploaderID: "@alice:example.com",
		Size:       4,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if midiaStore.savedMidia != nil {
		t.Fatal("expected DB to NOT be called when MinIO fails")
	}
}

func TestMediaServiceUploadDBErrorTriggersRollback(t *testing.T) {
	// MinIO ok + Postgres falha → arquivo deve ser deletado do MinIO (rollback compensatório)
	fileStore := &fakeFileStorage{}
	midiaStore := &fakeMidiaStorage{saveErr: errors.New("db connection lost")}
	svc := NewMediaService("example.com", fileStore, midiaStore, 0, nil)

	_, err := svc.Upload(context.Background(), UploadParams{
		Content:    strings.NewReader("data"),
		UploaderID: "@alice:example.com",
		Size:       4,
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !fileStore.deleteCalled {
		t.Fatal("expected Delete to be called on MinIO to rollback after DB failure")
	}
}

func TestMediaServiceUploadDefaultMaxSize(t *testing.T) {
	// maxSizeBytes <= 0 deve usar DefaultMaxUploadBytes sem entrar em panic
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 0, nil)

	if svc.maxSizeBytes != DefaultMaxUploadBytes {
		t.Fatalf("expected default max size %d, got %d", DefaultMaxUploadBytes, svc.maxSizeBytes)
	}
}

// Testes de Download / Thumbnail
 
func TestMediaServiceDownloadLocalSuccess(t *testing.T) {
	midiaStore := &fakeMidiaStorage{getResult: &domain.Midia{
		IDMidia:     "abc123",
		Origin:      "example.com",
		ContentType: "image/png",
		UploadName:  "avatar.png",
	}}
	svc := NewMediaService("example.com", &fakeFileStorage{}, midiaStore, 0, nil)
 
	result, err := svc.Download(context.Background(), "example.com", "abc123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer result.Content.Close()
 
	if result.ContentType != "image/png" {
		t.Fatalf("expected content_type image/png, got %s", result.ContentType)
	}
	if result.Filename != "avatar.png" {
		t.Fatalf("expected filename avatar.png, got %s", result.Filename)
	}
}
 
func TestMediaServiceDownloadLocalNotFound(t *testing.T) {
	// GetMidiaByID retorna nil, nil quando não encontrado, deve virar ErrMediaNotFound
	midiaStore := &fakeMidiaStorage{getResult: nil}
	svc := NewMediaService("example.com", &fakeFileStorage{}, midiaStore, 0, nil)
 
	_, err := svc.Download(context.Background(), "example.com", "nao-existe")
	if !errors.Is(err, ErrMediaNotFound) {
		t.Fatalf("expected ErrMediaNotFound, got %v", err)
	}
}
 
func TestMediaServiceDownloadRemoteProxiesToFetcher(t *testing.T) {
	fetcher := &fakeRemoteFetcher{
		content:     "conteúdo remoto",
		contentType: "video/mp4",
		filename:    "clip.mp4",
	}
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 0, fetcher)
 
	result, err := svc.Download(context.Background(), "outroservidor.com", "xyz789")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer result.Content.Close()
 
	if fetcher.calledWith.serverName != "outroservidor.com" {
		t.Fatalf("expected fetcher called with outroservidor.com, got %s", fetcher.calledWith.serverName)
	}
	if fetcher.calledWith.mediaID != "xyz789" {
		t.Fatalf("expected fetcher called with mediaID xyz789, got %s", fetcher.calledWith.mediaID)
	}
	if result.ContentType != "video/mp4" {
		t.Fatalf("expected content_type video/mp4, got %s", result.ContentType)
	}
 
	body, _ := io.ReadAll(result.Content)
	if string(body) != "conteúdo remoto" {
		t.Fatalf("expected proxied content to match, got %s", string(body))
	}
}
 
func TestMediaServiceDownloadRemoteWithoutFetcherIsNotFound(t *testing.T) {
	// remoteFetcher nil (federação de mídia desabilitada) deve virar ErrMediaNotFound, não pânico
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 0, nil)
 
	_, err := svc.Download(context.Background(), "outroservidor.com", "xyz789")
	if !errors.Is(err, ErrMediaNotFound) {
		t.Fatalf("expected ErrMediaNotFound when remoteFetcher is nil, got %v", err)
	}
}
 
func TestMediaServiceDownloadRemoteFetcherError(t *testing.T) {
	fetcher := &fakeRemoteFetcher{err: errors.New("servidor remoto offline")}
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 0, fetcher)
 
	_, err := svc.Download(context.Background(), "outroservidor.com", "xyz789")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
 
func TestMediaServiceThumbnailReusesDownload(t *testing.T) {
	// Thumbnail deve devolver exatamente o mesmo resultado que Download (sem redimensionar)
	midiaStore := &fakeMidiaStorage{getResult: &domain.Midia{
		IDMidia:     "abc123",
		Origin:      "example.com",
		ContentType: "image/jpeg",
		UploadName:  "photo.jpg",
	}}
	svc := NewMediaService("example.com", &fakeFileStorage{}, midiaStore, 0, nil)
 
	result, err := svc.Thumbnail(context.Background(), "example.com", "abc123")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer result.Content.Close()
 
	if result.ContentType != "image/jpeg" {
		t.Fatalf("expected content_type image/jpeg (original, no resizing), got %s", result.ContentType)
	}
}

func TestMediaServiceMaxUploadSize(t *testing.T) {
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 20*1024*1024, nil)

	if got := svc.MaxUploadSize(); got != 20*1024*1024 {
		t.Fatalf("expected 20971520, got %d", got)
	}
}

func TestMediaServiceMaxUploadSizeDefault(t *testing.T) {
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 0, nil)

	if got := svc.MaxUploadSize(); got != DefaultMaxUploadBytes {
		t.Fatalf("expected default %d, got %d", DefaultMaxUploadBytes, got)
	}
}