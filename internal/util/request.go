package util

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type WellKnownServer struct {
	Server string `json:"m.server"`
}

func ResolveWellKnown(server string) (string, error) {
	url := fmt.Sprintf("https://%s/.well-known/matrix/server", server)

	client := &http.Client{}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var wellKnownServer WellKnownServer
	if err := json.NewDecoder(resp.Body).Decode(&wellKnownServer); err != nil {
		return "", err
	}

	if wellKnownServer.Server == "" {
		return "", fmt.Errorf("no server found in well-known response")
	}

	return wellKnownServer.Server, nil
}
