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
}

func (f *fakeMidiaStorage) SaveMidia(_ context.Context, midia *domain.Midia) error {
	f.savedMidia = midia
	return f.saveErr
}

func (f *fakeMidiaStorage) GetMidiaByID(_ context.Context, _, _ string) (*domain.Midia, error) {
	return nil, nil
}

// Testes

func TestMediaServiceUploadSuccess(t *testing.T) {
	fileStore := &fakeFileStorage{}
	midiaStore := &fakeMidiaStorage{}
	svc := NewMediaService("example.com", fileStore, midiaStore, 10*1024*1024)

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
	svc := NewMediaService("example.com", &fakeFileStorage{}, midiaStore, 0)

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
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 100)

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
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 5)

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
	svc := NewMediaService("example.com", fileStore, midiaStore, 0)

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
	svc := NewMediaService("example.com", fileStore, midiaStore, 0)

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
	svc := NewMediaService("example.com", &fakeFileStorage{}, &fakeMidiaStorage{}, 0)

	if svc.maxSizeBytes != DefaultMaxUploadBytes {
		t.Fatalf("expected default max size %d, got %d", DefaultMaxUploadBytes, svc.maxSizeBytes)
	}
}