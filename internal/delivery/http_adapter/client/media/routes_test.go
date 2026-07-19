package media

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
	"github.com/caio-bernardo/dragonite/internal/usecase"
)

// Fakes

type routeFileStore struct {
	uploadErr error
}

func (f *routeFileStore) Upload(_ context.Context, _ string, _ io.Reader, _ int64, _ string) error {
	return f.uploadErr
}
func (f *routeFileStore) Download(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (f *routeFileStore) Delete(_ context.Context, _ string) error { return nil }

type routeMidiaStore struct {
	saveErr   error
	getResult *domain.Midia
	getErr    error
}

func (f *routeMidiaStore) SaveMidia(_ context.Context, _ *domain.Midia) error {
	return f.saveErr
}
func (f *routeMidiaStore) GetMidiaByID(_ context.Context, _, _ string) (*domain.Midia, error) {
	return f.getResult, f.getErr
}

// routeRemoteFetcher simula FederationService.FetchRemoteMedia para testar o proxy federado
type routeRemoteFetcher struct {
	content     string
	contentType string
	filename    string
	err         error
}

func (f *routeRemoteFetcher) FetchRemoteMedia(_ context.Context, _, _ string) (io.ReadCloser, string, string, error) {
	if f.err != nil {
		return nil, "", "", f.err
	}
	return io.NopCloser(strings.NewReader(f.content)), f.contentType, f.filename, nil
}

// ctxWithUser injeta o userID no context
func ctxWithUser(userID string) context.Context {
	return context.WithValue(context.Background(), types.UserIDKey, userID)
}

// Testes de Upload

func TestUploadMediaSuccess(t *testing.T) {
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 10*1024*1024, nil)
	h := NewHandler(svc)

	content := []byte("file content")
	req := httptest.NewRequest(http.MethodPost, "/_matrix/media/v3/upload?filename=avatar.png", bytes.NewReader(content))
	req = req.WithContext(ctxWithUser("@alice:example.com"))
	req.Header.Set("Content-Type", "image/png")
	req.ContentLength = int64(len(content))

	rec := httptest.NewRecorder()
	h.uploadMedia(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}

	var resp UploadResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.HasPrefix(resp.ContentURI, "mxc://") {
		t.Fatalf("expected content_uri to start with 'mxc://', got %s", resp.ContentURI)
	}
}

func TestUploadMediaTooLargeByContentLength(t *testing.T) {
	// Rejeição via Content-Length (< 5 bytes de limite, header diz 999)
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 5, nil)
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/_matrix/media/v3/upload", strings.NewReader("x"))
	req = req.WithContext(ctxWithUser("@alice:example.com"))
	req.ContentLength = 999 // header indica arquivo grande, rejeição rápida

	rec := httptest.NewRecorder()
	h.uploadMedia(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_TOO_LARGE")
}

func TestUploadMediaTooLargeByBody(t *testing.T) {
	// Rejeição via LimitReader quando Content-Length não é enviado
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 5, nil)
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/_matrix/media/v3/upload", strings.NewReader("123456789"))
	req = req.WithContext(ctxWithUser("@alice:example.com"))
	// ContentLength -1 = não enviado pelo cliente

	rec := httptest.NewRecorder()
	h.uploadMedia(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_TOO_LARGE")
}

func TestUploadMediaDefaultContentType(t *testing.T) {
	// Sem Content-Type no header → deve usar application/octet-stream e retornar 200
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 0, nil)
	h := NewHandler(svc)

	content := []byte("raw bytes")
	req := httptest.NewRequest(http.MethodPost, "/_matrix/media/v3/upload", bytes.NewReader(content))
	req = req.WithContext(ctxWithUser("@alice:example.com"))
	// Content-Type deliberadamente omitido

	rec := httptest.NewRecorder()
	h.uploadMedia(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadMediaInternalError(t *testing.T) {
	// Falha no MinIO → deve retornar 500 M_UNKNOWN
	fileStore := &routeFileStore{uploadErr: errors.New("minio down")}
	svc := usecase.NewMediaService("example.com", fileStore, &routeMidiaStore{}, 0, nil)
	h := NewHandler(svc)

	content := []byte("data")
	req := httptest.NewRequest(http.MethodPost, "/_matrix/media/v3/upload", bytes.NewReader(content))
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.uploadMedia(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_UNKNOWN")
}

// assertErrCode é um helper que verifica o campo errcode da resposta Matrix
func assertErrCode(t *testing.T, rec *httptest.ResponseRecorder, expected string) {
	t.Helper()
	var resp struct {
		ErrCode string `json:"errcode"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.ErrCode != expected {
		t.Fatalf("expected errcode %s, got %s", expected, resp.ErrCode)
	}
}

func newDownloadRequest(path, serverName, mediaID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.SetPathValue("serverName", serverName)
	req.SetPathValue("mediaId", mediaID)
	return req.WithContext(ctxWithUser("@alice:example.com"))
}

// Testes de downloadMedia

func TestDownloadMediaLocalSuccess(t *testing.T) {
	midiaStore := &routeMidiaStore{getResult: &domain.Midia{
		IDMidia:     "abc123",
		Origin:      "example.com",
		ContentType: "image/png",
		UploadName:  "avatar.png",
	}}
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, midiaStore, 0, nil)
	h := NewHandler(svc)

	req := newDownloadRequest("/_matrix/client/v1/media/download/example.com/abc123", "example.com", "abc123")
	rec := httptest.NewRecorder()
	h.downloadMedia(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("expected Content-Type image/png, got %s", ct)
	}
	disposition := rec.Header().Get("Content-Disposition")
	if !strings.HasPrefix(disposition, "inline") {
		t.Fatalf("expected inline disposition for image/png, got %s", disposition)
	}
	if !strings.Contains(disposition, `filename="avatar.png"`) {
		t.Fatalf("expected filename in disposition, got %s", disposition)
	}
}

func TestDownloadMediaNotFound(t *testing.T) {
	midiaStore := &routeMidiaStore{getResult: nil}
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, midiaStore, 0, nil)
	h := NewHandler(svc)

	req := newDownloadRequest("/_matrix/client/v1/media/download/example.com/nao-existe", "example.com", "nao-existe")
	rec := httptest.NewRecorder()
	h.downloadMedia(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_NOT_FOUND")
}

func TestDownloadMediaMissingPathParams(t *testing.T) {
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 0, nil)
	h := NewHandler(svc)

	// serverName e mediaId não foram setados via SetPathValue
	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v1/media/download//", nil)
	req = req.WithContext(ctxWithUser("@alice:example.com"))
	rec := httptest.NewRecorder()
	h.downloadMedia(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_BAD_JSON")
}

func TestDownloadMediaRemoteProxiesViaFederation(t *testing.T) {
	fetcher := &routeRemoteFetcher{
		content:     "bytes remotos",
		contentType: "application/pdf",
		filename:    "doc.pdf",
	}
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 0, fetcher)
	h := NewHandler(svc)

	req := newDownloadRequest("/_matrix/client/v1/media/download/outroservidor.com/xyz789", "outroservidor.com", "xyz789")
	rec := httptest.NewRecorder()
	h.downloadMedia(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	// application/pdf não está na lista inline-safe (image/audio/video/text) → attachment
	disposition := rec.Header().Get("Content-Disposition")
	if !strings.HasPrefix(disposition, "attachment") {
		t.Fatalf("expected attachment disposition for application/pdf, got %s", disposition)
	}
	if rec.Body.String() != "bytes remotos" {
		t.Fatalf("expected proxied body, got %s", rec.Body.String())
	}
}

func TestDownloadMediaRemoteWithoutFederationIsNotFound(t *testing.T) {
	// Sem RemoteMediaFetcher configurado, pedir mídia de outro servidor deve dar 404, não 500
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 0, nil)
	h := NewHandler(svc)

	req := newDownloadRequest("/_matrix/client/v1/media/download/outroservidor.com/xyz789", "outroservidor.com", "xyz789")
	rec := httptest.NewRecorder()
	h.downloadMedia(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_NOT_FOUND")
}

// Testes de thumbnailMedia

func TestThumbnailMediaReturnsOriginalFile(t *testing.T) {
	// confirma a simplificação: thumbnail devolve o arquivo original, sem redimensionar
	midiaStore := &routeMidiaStore{getResult: &domain.Midia{
		IDMidia:     "abc123",
		Origin:      "example.com",
		ContentType: "image/jpeg",
		UploadName:  "photo.jpg",
	}}
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, midiaStore, 0, nil)
	h := NewHandler(svc)

	req := newDownloadRequest("/_matrix/client/v1/media/thumbnail/example.com/abc123", "example.com", "abc123")
	rec := httptest.NewRecorder()
	h.thumbnailMedia(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Fatalf("expected Content-Type image/jpeg (original), got %s", ct)
	}
}

func TestThumbnailMediaNotFound(t *testing.T) {
	midiaStore := &routeMidiaStore{getResult: nil}
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, midiaStore, 0, nil)
	h := NewHandler(svc)

	req := newDownloadRequest("/_matrix/client/v1/media/thumbnail/example.com/nao-existe", "example.com", "nao-existe")
	rec := httptest.NewRecorder()
	h.thumbnailMedia(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	assertErrCode(t, rec, "M_NOT_FOUND")
}

// Testes de mediaConfig

func TestMediaConfigSuccess(t *testing.T) {
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 10*1024*1024, nil)
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v1/media/config", nil)
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.mediaConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}

	var resp MediaConfigResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.MUploadSize == nil || *resp.MUploadSize != 10*1024*1024 {
		t.Fatalf("expected m.upload.size 10485760, got %v", resp.MUploadSize)
	}
}

func TestMediaConfigUsesDefaultWhenUnconfigured(t *testing.T) {
	// maxSizeBytes <= 0 no construtor do service → deve cair no DefaultMaxUploadBytes
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 0, nil)
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/_matrix/client/v1/media/config", nil)
	req = req.WithContext(ctxWithUser("@alice:example.com"))

	rec := httptest.NewRecorder()
	h.mediaConfig(rec, req)

	var resp MediaConfigResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.MUploadSize == nil || *resp.MUploadSize != usecase.DefaultMaxUploadBytes {
		t.Fatalf("expected default max upload size %d, got %v", usecase.DefaultMaxUploadBytes, resp.MUploadSize)
	}
}
