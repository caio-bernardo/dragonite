package http_adapter

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIsAllowedWellKnownMatrixFile(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		allowed  bool
	}{
		{name: "client allowed", fileName: "client", allowed: true},
		{name: "server allowed", fileName: "server", allowed: true},
		{name: "support allowed", fileName: "support", allowed: true},
		{name: "empty denied", fileName: "", allowed: false},
		{name: "path denied", fileName: "foo/bar", allowed: false},
		{name: "traversal denied", fileName: "../client", allowed: false},
		{name: "unknown denied", fileName: "other", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAllowedWellKnownMatrixFile(tt.fileName); got != tt.allowed {
				t.Fatalf("expected %v for %q, got %v", tt.allowed, tt.fileName, got)
			}
		})
	}
}

func TestWellKnownMatrixRouteServesWhitelistedFile(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "static", ".well-known", "matrix", "client")
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filePath, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWD)
	})
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/matrix/client", nil)
	req.SetPathValue("fileName", "client")
	rec := httptest.NewRecorder()

	s.wellKnownMatrixHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != `{"ok":true}` {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestWellKnownMatrixRouteRejectsUnknownFile(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/.well-known/matrix/unknown", nil)
	req.SetPathValue("fileName", "unknown")
	rec := httptest.NewRecorder()

	s.wellKnownMatrixHandler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}
}
