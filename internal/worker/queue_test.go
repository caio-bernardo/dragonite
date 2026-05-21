package worker

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"context"

	"github.com/caio-bernardo/dragonite/internal/types"
)

type capturedRequest struct {
	headers http.Header
	path    string
	method  string
	body    []byte
}

func newTestServerConfig(t *testing.T) (types.ServerConfig, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg := types.ServerConfig{
		ServerName: "origin.test",
		KeyID:      "ed25519:test",
		PublicKey:  pub,
		PrivateKey: priv,
	}
	return cfg, pub
}

func TestWorkerQueue_Push_CreatesWorkersPerDest(t *testing.T) {
	cfg, _ := newTestServerConfig(t)

	var reqCount atomic.Int32
	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv1.Close)

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv2.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	wq := NewWorkerQueue(ctx, cfg)

	wq.Push(Job{Dest: srv1.URL, Type: PDU, Payload: []byte(`{"p":1}`)})

	wq.mu.RLock()
	got := len(wq.workers)
	wq.mu.RUnlock()
	if got != 1 {
		t.Fatalf("workers count after first dest: got %d want 1", got)
	}

	wq.Push(Job{Dest: srv1.URL, Type: PDU, Payload: []byte(`{"p":2}`)})
	wq.mu.RLock()
	got = len(wq.workers)
	wq.mu.RUnlock()
	if got != 1 {
		t.Fatalf("workers count after same dest: got %d want 1", got)
	}

	wq.Push(Job{Dest: srv2.URL, Type: PDU, Payload: []byte(`{"p":3}`)})
	wq.mu.RLock()
	got = len(wq.workers)
	wq.mu.RUnlock()
	if got != 2 {
		t.Fatalf("workers count after second dest: got %d want 2", got)
	}

	// Stop workers to avoid goroutine leaks.
	cancel()
}

func TestWorkerQueue_BatchesByMaxBatchSize_SendsSingleRequest(t *testing.T) {
	cfg, pub := newTestServerConfig(t)

	var reqCount atomic.Int32
	reqCh := make(chan capturedRequest, 2)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		reqCount.Add(1)
		reqCh <- capturedRequest{
			headers: r.Header.Clone(),
			path:    r.URL.Path,
			method:  r.Method,
			body:    b,
		}

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	wq := NewWorkerQueue(ctx, cfg)

	// 50 jobs => flush immediately by maxBatchSize.
	for i := range 40 {
		payload := []byte(`{"p":` + itoa(i) + `}`)
		wq.Push(Job{Dest: srv.URL, Type: PDU, Payload: payload})
	}
	for i := range 10 {
		payload := []byte(`{"e":` + itoa(i) + `}`)
		wq.Push(Job{Dest: srv.URL, Type: EDU, Payload: payload})
	}

	var got capturedRequest
	select {
	case got = <-reqCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for batched request")
	}

	if got.method != http.MethodPut {
		t.Fatalf("method: got %q want %q", got.method, http.MethodPut)
	}
	if got.path == "" || got.path[:len("/_matrix/federation/v1/send/")] != "/_matrix/federation/v1/send/" {
		t.Fatalf("unexpected path: %q", got.path)
	}

	// Verify signature created using our config key.
	auth := got.headers.Get("Authorization")
	_, _, sigB64 := parseXMatrixAuthHeader(t, auth)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("base64 decode sig: %v", err)
	}
	if !ed25519.Verify(pub, got.body, sig) {
		t.Fatalf("signature verification failed")
	}

	var txn Transaction
	if err := json.Unmarshal(got.body, &txn); err != nil {
		t.Fatalf("unmarshal txn: %v", err)
	}

	if txn.Origin != cfg.ServerName {
		t.Fatalf("Origin: got %q want %q", txn.Origin, cfg.ServerName)
	}
	if len(txn.PDUs) != 40 {
		t.Fatalf("PDUs length: got %d want %d", len(txn.PDUs), 40)
	}
	if len(txn.EDUs) != 10 {
		t.Fatalf("EDUs length: got %d want %d", len(txn.EDUs), 10)
	}

	// Ensure we only sent one request (give a short grace period).
	time.Sleep(200 * time.Millisecond)
	if c := reqCount.Load(); c != 1 {
		t.Fatalf("request count: got %d want 1", c)
	}

	cancel()
}

func TestWorkerQueue_FlushesPendingBatchOnContextCancel(t *testing.T) {
	cfg, _ := newTestServerConfig(t)

	reqCh := make(chan capturedRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		reqCh <- capturedRequest{
			headers: r.Header.Clone(),
			path:    r.URL.Path,
			method:  r.Method,
			body:    b,
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	wq := NewWorkerQueue(ctx, cfg)

	wq.Push(Job{Dest: srv.URL, Type: PDU, Payload: []byte(`{"p":1}`)})

	// Wait until the job has been consumed from the channel buffer so it is in the worker's batch.
	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		wq.mu.RLock()
		ch := wq.workers[srv.URL]
		l := 0
		if ch != nil {
			l = len(ch)
		}
		wq.mu.RUnlock()

		if ch != nil && l == 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("timeout waiting for worker to consume pushed job")
		}
		time.Sleep(2 * time.Millisecond)
	}

	cancel()
	// Flush on cancel should happen before the 500ms timer fires.
	select {
	case <-reqCh:
		// ok
	case <-time.After(450 * time.Millisecond):
		t.Fatalf("timeout waiting for flush on context cancel (should be < 500ms)")
	}
}

func itoa(i int) string {
	// Small local helper to avoid pulling strconv into multiple tests.
	if i == 0 {
		return "0"
	}

	neg := false
	if i < 0 {
		neg = true
		i = -i
	}

	var b [32]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + (i % 10))
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
