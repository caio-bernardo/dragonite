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
	saveErr error
}

func (f *routeMidiaStore) SaveMidia(_ context.Context, _ *domain.Midia) error {
	return f.saveErr
}
func (f *routeMidiaStore) GetMidiaByID(_ context.Context, _, _ string) (*domain.Midia, error) {
	return nil, nil
}

// ctxWithUser injeta o userID no context
func ctxWithUser(userID string) context.Context {
	return context.WithValue(context.Background(), types.UserIDKey, userID)
}

// Testes

func TestUploadMediaSuccess(t *testing.T) {
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 10*1024*1024)
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
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 5)
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
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 5)
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
	svc := usecase.NewMediaService("example.com", &routeFileStore{}, &routeMidiaStore{}, 0)
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
	svc := usecase.NewMediaService("example.com", fileStore, &routeMidiaStore{}, 0)
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
