package worker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Transaction struct {
	EDUs           []json.RawMessage `json:"edus,omitempty"`
	Origin         string            `json:"origin"`
	OriginServerTS int64             `json:"origin_server_ts"`
	PDUs           []json.RawMessage `json:"pdus"`
}

func NewTransaction(serverName string, batch []Job) Transaction {

	var pdus []json.RawMessage
	var edus []json.RawMessage

	for _, job := range batch {
		if job.Type == EDU {
			edus = append(edus, json.RawMessage(job.Payload))
		} else {
			pdus = append(pdus, json.RawMessage(job.Payload))
		}
	}

	return Transaction{
		EDUs:           edus,
		Origin:         serverName,
		OriginServerTS: time.Now().UnixMilli(),
		PDUs:           pdus,
	}
}

func sendTransaction(destURL, txnID string, txn Transaction, serverName string, keyID string, privateKey ed25519.PrivateKey) error {

	payloadBytes, err := json.Marshal(txn)
	if err != nil {
		return fmt.Errorf("Failed to marshal transaction: %w", err)
	}

	signBytes := ed25519.Sign(privateKey, payloadBytes)
	signature := base64.StdEncoding.EncodeToString(signBytes)

	authHeader := fmt.Sprintf(`X-Matrx origin="%s",key="%s",sig="%s"`, serverName, keyID, signature)

	endpoint := fmt.Sprintf("%s/_matrix/federation/v1/send/%s", destURL, txnID)
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("Failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
