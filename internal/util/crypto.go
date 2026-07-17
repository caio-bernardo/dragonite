package util

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caio-bernardo/dragonite/internal/domain"
)

func GenerateServerKey(serverName string, version string) (string, ed25519.PublicKey, ed25519.PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return fmt.Sprintf("ed25519:%s", version), pubKey, privKey, nil
}

func SignMatrixEvent(event *domain.Evento, serverName, keyID string, privateKey ed25519.PrivateKey) (json.RawMessage, error) {
	// 1. Transformamos o evento num mapa genérico para manipulação flexível
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}

	var eventMap map[string]any
	if err := json.Unmarshal(eventBytes, &eventMap); err != nil {
		return nil, err
	}

	// 2. Removemos os campos que NÃO DEVEM fazer parte da assinatura
	delete(eventMap, "signatures")
	delete(eventMap, "unsigned")
	delete(eventMap, "event_id")

	// 3. Geramos o Canonical JSON
	// Nota: Em Go, json.Marshal aplica a ordem alfabética nas chaves de um map[string]any nativamente,
	// e não adiciona espaços em branco (que é exatamente o que o Canonical JSON do Matrix exige para o básico).
	canonicalBytes, err := json.Marshal(eventMap)
	if err != nil {
		return nil, err
	}

	// 4. Assinamos os bytes do Canonical JSON com a chave Ed25519
	signature := ed25519.Sign(privateKey, canonicalBytes)

	// 5. O Matrix espera a assinatura em Raw URLEncoded Base64 (sem padding "=")
	encodedSig := base64.RawStdEncoding.EncodeToString(signature)

	// 6. Montamos o objeto de assinatura final exigido pelo spec
	// Formato: { "nome_do_servidor": { "ed25519:kid": "assinatura_base64" } }
	sigObject := map[string]map[string]string{
		serverName: {
			fmt.Sprintf("%s", keyID): encodedSig,
		},
	}

	return json.Marshal(sigObject)
}

func GenerateS2SAuthHeader(serverName, keyID string, privateKey ed25519.PrivateKey, method, uri, destination string, content any) (string, error) {
	signObj := map[string]any{
		"method":      method,
		"uri":         uri,
		"origin":      serverName,
		"destination": destination,
	}

	if content != nil {
		signObj["content"] = content
	}

	canonicalBytes, err := CanonicalJSON(signObj)
	if err != nil {
		return "", err
	}

	signature := ed25519.Sign(privateKey, canonicalBytes)

	encodedSig := base64.RawStdEncoding.EncodeToString(signature)

	authHeader := fmt.Sprintf(`X-Matrix origin="%s",key="%s",sig="%s"`, serverName, keyID, encodedSig)

	return authHeader, nil
}

// FetchRemoteServerKey busca a chave pública ed25519 de um servidor Matrix remoto
func FetchRemoteServerKey(serverName string) (string, ed25519.PublicKey, error) {
	url := fmt.Sprintf("http://%s/_matrix/key/v2/server", serverName)
	resp, err := http.Get(url)
	if err != nil {
		return "", nil, fmt.Errorf("failed to fetch key from %s: %w", serverName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("unexpected status %d fetching key from %s", resp.StatusCode, serverName)
	}

	var body struct {
		VerifyKeys map[string]struct {
			Key string `json:"key"`
		} `json:"verify_keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", nil, fmt.Errorf("failed to decode key response: %w", err)
	}

	for keyID, vk := range body.VerifyKeys {
		keyBytes, err := base64.RawStdEncoding.DecodeString(vk.Key)
		if err != nil {
			continue
		}
		return keyID, ed25519.PublicKey(keyBytes), nil
	}

	return "", nil, fmt.Errorf("no valid ed25519 key found for server %s", serverName)
}
