package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetLoginFlows(t *testing.T) {
	h := NewHandler()
	server := httptest.NewServer(http.HandlerFunc(h.getLogin))
	defer server.Close()
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("error making request to server. Err: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status OK; got %v", resp.Status)
	}

	expected := `{"flows":[{"type":"m.login.password"}]}`
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading response body. Err: %v", err)
	}
	if expected != string(body) {
		t.Errorf("expected response body to be %v; got %v", expected, string(body))
	}

}

func TestPostLogin(t *testing.T) {

}
