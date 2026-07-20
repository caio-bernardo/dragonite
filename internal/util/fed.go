package util

import (
	"context"
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

// FederationScheme é o esquema HTTP usado em toda chamada S2S (server-to-server) do
// projeto: chamadas outbound em federation_service.go e a busca de chave remota em
// FetchRemoteServerKey. A spec do Matrix exige HTTPS em produção, mas o ambiente de
// desenvolvimento/teste ainda não tem TLS configurado entre homeservers. Mude só esta
// constante quando TLS for configurado, não hardcode "http"/"https" em outro lugar.
const FederationScheme = "http"

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

	client := &http.Client{Timeout: 3 * time.Second}

	// Tentar o /.well-known/matrix/server
	wellKnownURL := fmt.Sprintf("%s://%s/.well-known/matrix/server", FederationScheme, serverName)
	resp, err := client.Get(wellKnownURL)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		var wkResponse WellKnowServerResponse
		if err := json.NewDecoder(resp.Body).Decode(&wkResponse); err == nil && wkResponse.MServer != "" {
			return wkResponse.MServer, nil
		}
	}

	// Tentar DNS SRV — com timeout explícito. net.LookupSRV puro não tem timeout e é o
	// que travava ~30s quando o hostname não resolvia de verdade (caso do dragonite.com)
	srvCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, addrs, err := net.DefaultResolver.LookupSRV(srvCtx, "matrix", "tcp", serverName)
	if err == nil && len(addrs) > 0 {
		target := strings.TrimSuffix(addrs[0].Target, ".")
		return fmt.Sprintf("%s:%d", target, addrs[0].Port), nil
	}
	// fallback porta 8448
	return fmt.Sprintf("%s:8448", serverName), nil
}
