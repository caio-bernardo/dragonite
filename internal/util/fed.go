package util

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type WellKnowServerResponse struct {
	MServer string `json:"m.server"`
}

// isRemoteUser returns true if the user is remote (i.e. not on the same server)
func IsRemoteUser(userID, serverName string) bool {

	parts := strings.SplitN(userID, ":", 2)
	if len(parts) != 2 {
		return false
	}
	return parts[1] != serverName
}

func ResolveServerName(serverName string) (string, error) {

	// se porta explicíta usar o domínio direto
	if strings.Contains(serverName, ":") {
		return serverName, nil
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Tentar o /.well-known/matrix/server
	wellKnownURL := "http://" + serverName + "/.well-known/matrix/server"
	resp, err := client.Get(wellKnownURL)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		var wkResponse WellKnowServerResponse
		if err := json.NewDecoder(resp.Body).Decode(&wkResponse); err == nil && wkResponse.MServer != "" {
			return wkResponse.MServer, nil
		}
	}

	// Tentar DNS SRV
	_, addrs, err := net.LookupSRV("matrix", "tcp", serverName)
	if err == nil && len(addrs) > 0 {
		// O Go já ordena pelos pesos (Priority/Weight) do SRV
		target := strings.TrimSuffix(addrs[0].Target, ".")
		return fmt.Sprintf("%s:%d", target, addrs[0].Port), nil

	}
	// fallback porta 8448
	return fmt.Sprintf("%s:8448", serverName), nil
}
