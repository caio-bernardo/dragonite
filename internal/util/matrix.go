package util

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/gibson042/canonicaljson-go"
)

func CreateRoomID(serverName string) string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("!%s:%s", time.Now().Format(time.RFC3339Nano), serverName)
	}
	roomID := base64.RawURLEncoding.EncodeToString(bytes)
	return fmt.Sprintf("!%s:%s", roomID, serverName)
}

func ExtractDomainFromUserID(userID string) string {
	parts := strings.SplitN(userID, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// hashMatrixEvent calculates the Canonical JSON SHA-256 hash of an event
// and returns the URL-safe Base64 encoded Event ID.
func HashMatrixEvent(event *domain.Evento) (string, error) {
	// 1. Convert the Go struct into a generic map.
	// We marshal and unmarshal first to respect any `json:",omitempty"` tags
	// and ensure the data matches what will actually go over the wire.
	rawBytes, err := CanonicalJSON(event)
	if err != nil {
		return "", fmt.Errorf("failed to initial marshal: %w", err)
	}

	var eventMap map[string]any
	if err := canonicaljson.Unmarshal(rawBytes, &eventMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal to map: %w", err)
	}

	// 2. STRIP EXCLUDED FIELDS
	// The Matrix spec strictly dictates that metadata and signatures
	// cannot be part of the hash, otherwise the hash would change every time
	// another server signs it!
	delete(eventMap, "unsigned")
	delete(eventMap, "signatures")
	delete(eventMap, "event_id")

	// 3. GENERATE CANONICAL JSON
	// Go's json package automatically sorts map keys alphabetically, which
	// handles the hardest part of the Matrix Canonical JSON requirement.
	canonicalBytes, err := CanonicalJSON(eventMap)
	if err != nil {
		return "", fmt.Errorf("failed to encode canonical json: %w", err)
	}

	// 4. HASH WITH SHA-256
	hash := sha256.Sum256(canonicalBytes)

	// 5. ENCODE TO UNPADDED URL-SAFE BASE64
	// Matrix Room Versions 4+ require RawURLEncoding (which omits the '=' padding
	// at the end and uses '-' and '_' instead of '+' and '/').
	base64Hash := base64.RawURLEncoding.EncodeToString(hash[:])

	// 6. PREFIX WITH '$'
	eventID := fmt.Sprintf("$%s", base64Hash)

	return eventID, nil
}

func GenerateNextSinceToken(
	since domain.SyncToken,
	eventos []domain.Evento,
	// presence []domain.PresenceEvento
	// receipts []domain.Receipts
) domain.SyncToken {
	nextToken := since

	// IMPORTANT: assumindo que os eventos estão ordenados por stream_ordering
	if len(eventos) > 0 {
		// Assuming newEvents is ordered chronologically (ORDER BY stream_ordering ASC)
		// We take the highest stream_ordering from the very last event.
		ultimoEvento := eventos[len(eventos)-1]
		nextToken.TimelinePosition = ultimoEvento.StreamOrdering
	}
	// TODO: implementar presence e receipts um dia ai
	/*
		if len(newPresence) > 0 {
			nextToken.PresencePosition = newPresence[len(newPresence)-1].StreamOrdering
		}
		if len(newReceipts) > 0 {
			nextToken.ReceiptPosition = newReceipts[len(newReceipts)-1].StreamOrdering
		}
	*/

	return nextToken
}
