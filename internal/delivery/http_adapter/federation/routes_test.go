package federation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caio-bernardo/dragonite/internal/usecase"
	"github.com/caio-bernardo/dragonite/internal/util"
)

type fakeSystemStorage struct{}

func (s *fakeSystemStorage) PingDB() map[string]string {
	return map[string]string{"status": "up"}
}

func TestFederationGetVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sys := usecase.NewSystemService("example.com", "1.0.0", pub, priv, "ed25519:1", &fakeSystemStorage{})
	h := NewHandler(sys, nil, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/version", nil)

	h.getVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp VersionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Server.Name != "example.com" || resp.Server.Version != "1.0.0" {
		t.Fatalf("unexpected server info: %+v", resp.Server)
	}
}

func TestFederationGetServerKeySignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sys := usecase.NewSystemService("example.com", "1.0.0", pub, priv, "ed25519:1", &fakeSystemStorage{})
	h := NewHandler(sys, nil, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/key/v2/server", nil)

	before := time.Now()
	h.getServerKey(rec, req)
	after := time.Now()

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp ServerKeyResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ServerName != "example.com" {
		t.Fatalf("expected server_name example.com, got %s", resp.ServerName)
	}
	if resp.ValidUntilTS <= before.UnixMilli() || resp.ValidUntilTS <= after.UnixMilli() {
		t.Fatalf("expected valid_until_ts in the future")
	}

	sig := resp.Signatures["example.com"]["ed25519:1"]
	sigBytes, err := base64.RawStdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	resp.Signatures = nil
	canonical, err := util.CanonicalJSON(resp)
	if err != nil {
		t.Fatalf("canonical json: %v", err)
	}

	if !ed25519.Verify(pub, canonical, sigBytes) {
		t.Fatalf("expected signature to verify")
	}
}
