package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetVersionsHandler(t *testing.T) {
	h := NewHandler()
	server := httptest.NewServer(http.HandlerFunc(h.getVersions))
	defer server.Close()
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("error making request to server. Err: %v", err)
	}
	defer resp.Body.Close()
	// Assertions
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK; got %v", resp.Status)
	}
	expected := "{\"versions\":[\"r0.0.5\",\"v1.18\"]}"
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body. Err: %v", err)
	}
	if expected != string(body) {
		t.Errorf("expected response body to be %v; got %v", expected, string(body))
	}
}
