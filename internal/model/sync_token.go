package model

import (
	"encoding/json"
	"fmt"
)

type SyncToken struct {
	RoomEvents  int64
	Receipts    int64
	AccountData int64
}

func (t SyncToken) Encode() string {
	return fmt.Sprintf("s%d_%d_%d", t.RoomEvents, t.Receipts, t.AccountData)
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
	_, err := fmt.Sscanf(t, "s%d_%d_%d", &token.RoomEvents, &token.Receipts, &token.AccountData)
	if err != nil {
		return SyncToken{
			RoomEvents:  0,
			Receipts:    0,
			AccountData: 0,
		}
	}
	return token
}
