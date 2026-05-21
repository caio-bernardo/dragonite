package worker

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func parseXMatrixAuthHeader(t *testing.T, header string) (origin, keyID, sigB64 string) {
	t.Helper()

	if !strings.HasPrefix(header, "X-Matrx ") {
		t.Fatalf("unexpected Authorization header prefix: %q", header)
	}

	rest := strings.TrimPrefix(header, "X-Matrx ")
	parts := strings.Split(rest, ",")
	kv := map[string]string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			t.Fatalf("invalid auth part %q in header %q", part, header)
		}
		v = strings.TrimSpace(v)
		v = strings.TrimPrefix(v, "\"")
		v = strings.TrimSuffix(v, "\"")
		kv[k] = v
	}

	origin = kv["origin"]
	keyID = kv["key"]
	sigB64 = kv["sig"]

	if origin == "" || keyID == "" || sigB64 == "" {
		t.Fatalf("missing origin/key/sig in Authorization header: %q", header)
	}

	return origin, keyID, sigB64
}

func TestNewTransaction_SplitsJobsAndSetsFields(t *testing.T) {
	batch := []Job{
		{Type: PDU, Payload: []byte(`{"p":1}`)},
		{Type: EDU, Payload: []byte(`{"e":1}`)},
		{Type: PDU, Payload: []byte(`{"p":2}`)},
	}

	before := time.Now().UnixMilli()
	txn := NewTransaction("example.org", batch)
	after := time.Now().UnixMilli()

	if txn.Origin != "example.org" {
		t.Fatalf("Origin: got %q want %q", txn.Origin, "example.org")
	}

	if txn.OriginServerTS < before || txn.OriginServerTS > after {
		t.Fatalf("OriginServerTS out of range: got %d, want between %d and %d", txn.OriginServerTS, before, after)
	}

	if got, want := len(txn.PDUs), 2; got != want {
		t.Fatalf("PDUs length: got %d want %d", got, want)
	}
	if got, want := len(txn.EDUs), 1; got != want {
		t.Fatalf("EDUs length: got %d want %d", got, want)
	}

	if string(txn.PDUs[0]) != `{"p":1}` || string(txn.PDUs[1]) != `{"p":2}` {
		t.Fatalf("unexpected PDUs: %q", []string{string(txn.PDUs[0]), string(txn.PDUs[1])})
	}
	if string(txn.EDUs[0]) != `{"e":1}` {
		t.Fatalf("unexpected EDUs: %q", string(txn.EDUs[0]))
	}
}

func TestSendTransaction_SendsSignedPUTRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	serverName := "origin.example"
	keyID := "ed25519:test"
	txnID := "t123"

	txn := Transaction{
		Origin:         serverName,
		OriginServerTS: 123456789,
		PDUs:           []json.RawMessage{json.RawMessage(`{"p":1}`)},
		EDUs:           []json.RawMessage{json.RawMessage(`{"e":1}`)},
	}

	reqCh := make(chan *http.Request, 1)
	bodyCh := make(chan []byte, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		select {
		case reqCh <- r:
		default:
		}
		select {
		case bodyCh <- b:
		default:
		}

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	if err := sendTransaction(srv.URL, txnID, txn, serverName, keyID, priv); err != nil {
		t.Fatalf("sendTransaction returned error: %v", err)
	}

	var req *http.Request
	select {
	case req = <-reqCh:
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for request")
	}

	var body []byte
	select {
	case body = <-bodyCh:
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for request body")
	}

	if req.Method != http.MethodPut {
		t.Fatalf("method: got %q want %q", req.Method, http.MethodPut)
	}
	if req.URL.Path != "/_matrix/federation/v1/send/"+txnID {
		t.Fatalf("path: got %q want %q", req.URL.Path, "/_matrix/federation/v1/send/"+txnID)
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type: got %q want %q", ct, "application/json")
	}

	auth := req.Header.Get("Authorization")
	gotOrigin, gotKeyID, sigB64 := parseXMatrixAuthHeader(t, auth)
	if gotOrigin != serverName {
		t.Fatalf("auth origin: got %q want %q", gotOrigin, serverName)
	}
	if gotKeyID != keyID {
		t.Fatalf("auth key: got %q want %q", gotKeyID, keyID)
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("base64 decode sig: %v", err)
	}
	if !ed25519.Verify(pub, body, sig) {
		t.Fatalf("signature verification failed")
	}
}

func TestSendTransaction_Non200ReturnsError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	txn := Transaction{Origin: "x", OriginServerTS: 1, PDUs: []json.RawMessage{json.RawMessage(`{"p":1}`)}}

	err = sendTransaction(srv.URL, "t1", txn, "origin", "key", priv)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "Unexpected status code") {
		t.Fatalf("unexpected error: %v", err)
	}
}
