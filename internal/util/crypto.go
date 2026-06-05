package util

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"encoding/base64"
    "encoding/json"

	"github.com/caio-bernardo/dragonite/internal/types"
)

func GenerateServerKey(serverName string, version string) (types.ServerKeyPair, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return types.ServerKeyPair{}, fmt.Errorf("failed to generate key: %w", err)
	}
	return types.ServerKeyPair{
		Key:     fmt.Sprintf("ed25519:%s", version),
		PubKey:  pubKey,
		PrivKey: privKey,
	}, nil
}

// FetchRemoteServerKey busca a chave pública de um servidor Matrix remoto
// Faz GET https://<serverName>/_matrix/key/v2/server e retorna a primeira chave ed25519 encontrada em verify_keys.
func FetchRemoteServerKey(serverName string) (string, ed25519.PublicKey, error) {
    url := fmt.Sprintf("https://%s/_matrix/key/v2/server", serverName)
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
        return "", nil, fmt.Errorf("failed to decode key response from %s: %w", serverName, err)
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