package domain

import (
	"encoding/json"
	"fmt"
)

type SyncToken struct {
	TimelinePosition int64
	PresencePosition int64
	ReceiptPosition  int64
	ToDevicePosition int64
}

func (t SyncToken) Encode() string {
	return fmt.Sprintf("s%d_%d_%d_%d", t.TimelinePosition, t.PresencePosition, t.ReceiptPosition, t.ToDevicePosition)
}

func (t SyncToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Encode())
}

func (t *SyncToken) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*t = ParseToken(s)
	return nil
}

func ParseToken(t string) SyncToken {
	var token SyncToken
	_, err := fmt.Sscanf(t, "s%d_%d_%d_%d", &token.TimelinePosition, &token.PresencePosition, &token.ReceiptPosition, &token.ToDevicePosition)
	if err != nil {
		return SyncToken{}
	}
	return token
}
