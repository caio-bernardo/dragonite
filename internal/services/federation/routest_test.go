package federation

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	_ "github.com/joho/godotenv/autoload"
)

func NewTestHandler() *Handler {

	return NewHandler()
}

func TestFederationVersion(t *testing.T) {
	h := NewTestHandler()
	server := httptest.NewServer(http.HandlerFunc(h.getVersion))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	expectedName := os.Getenv("SERVER_NAME")
	expectBody := fmt.Sprintf(`{"server":{"name":"%s","version":"%s"}}`, expectedName, "1.0.0")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != expectBody {
		t.Errorf("expected body %s, got %s", expectBody, string(body))
	}
}
