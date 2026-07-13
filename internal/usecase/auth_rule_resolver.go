package usecase

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/caio-bernardo/dragonite/internal/domain"
)

// Resolves Authentication Event Dependencies
type AuthRuleResolver struct {
	canalRepo CanalStorage
}

func NewAuthRuleResolver(canalRepo CanalStorage) *AuthRuleResolver {
	return &AuthRuleResolver{canalRepo: canalRepo}
}

func (r *AuthRuleResolver) ResolveEventDependencies(
	ctx context.Context,
	roomID, sender string,
	eventType string,
	stateKey *string,
) ([]string, []string, error) {

	// 1. Resolve PrevEvents (The tips of the DAG)
	// This is simply querying the room_forward_extremities table.
	prevEvents, err := r.canalRepo.GetForwardExtremities(ctx, roomID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get extremities: %w", err)
	}

	// 2. Resolve AuthEvents (The VIP Pass)
	// The exact state events needed change based on what kind of event is being sent.
	// But almost ALL events require at least the create, power_levels, and sender's membership.

	authEvents := make([]string, 0)

	// Helper to fetch and append state safely
	appendState := func(stateType, stateKey string) {
		if eventID, found := r.canalRepo.GetStateEventID(ctx, roomID, stateType, stateKey); found {
			authEvents = append(authEvents, eventID)
		}
	}

	// ALWAYS REQUIRED: The room creation event
	appendState("m.room.create", "")

	// ALWAYS REQUIRED: The room power levels
	appendState("m.room.power_levels", "")

	// ALWAYS REQUIRED: The sender's membership (proving they are in the room)
	appendState("m.room.member", sender)

	// CONDITIONAL: If they are inviting someone, we also need the invitee's current membership state
	if eventType == "m.room.member" && stateKey != nil {
		// (Assuming you passed the target stateKey into this function)
		appendState("m.room.member", *stateKey)

		// And we need the join_rules to see if invites are allowed
		appendState("m.room.join_rules", "")
	}

	return prevEvents, authEvents, nil
}

// CheckAuth evaluates whether a candidate event is authorized against an in-memory partial StateMap.
// This is strictly used by State Resolution v2 to validate events without querying the database.
func (r *AuthRuleResolver) CheckAuth(
	ctx context.Context,
	ev *domain.Evento,
	currentState domain.StateMap,
	eventsMap map[string]*domain.Evento,
) bool {
	// 1. The Genesis event (m.room.create) is always authorized if it is the room creator
	if ev.Tipo == "m.room.create" {
		return true
	}

	// Helper to safely extract an event from the in-memory currentState accumulator
	getStateEvent := func(eType, sKey string) *domain.Evento {
		tuple := domain.NewStateTuple(eType, &sKey)
		if id, exists := currentState[tuple]; exists {
			return eventsMap[id]
		}
		return nil
	}

	// 2. Fetch baseline room control events from our in-memory accumulator
	plEvent := getStateEvent("m.room.power_levels", "")
	createEvent := getStateEvent("m.room.create", "")

	// Helper to calculate a user's effective power level from the accumulated state
	getUserPowerLevel := func(userID string) int64 {
		if plEvent == nil {
			// If power levels don't exist yet, the room creator implicitly has PL 100, everyone else 0
			if createEvent != nil && createEvent.Sender == userID {
				return 100
			}
			return 0
		}

		var content struct {
			Users        map[string]int64 `json:"users"`
			UsersDefault int64            `json:"users_default"`
		}
		if err := json.Unmarshal(plEvent.Content, &content); err == nil {
			if pl, exists := content.Users[userID]; exists {
				return pl
			}
			return content.UsersDefault
		}
		return 0
	}

	senderPL := getUserPowerLevel(ev.Sender)

	// 3. Evaluate rules based on the event type being candidate-tested
	switch ev.Tipo {
	case "m.room.member":
		var content struct {
			Membership string `json:"membership"`
		}
		if err := json.Unmarshal(ev.Content, &content); err != nil {
			return false
		}

		targetUserID := ""
		if ev.StateKey != nil {
			targetUserID = *ev.StateKey
		}

		// Self-joins (entering a room) pass basic structural auth in state res
		if content.Membership == "join" && targetUserID == ev.Sender {
			return true
		}

		// For kicks, bans, or invites of OTHER users, sender must have PL > target's PL
		if targetUserID != ev.Sender {
			targetPL := getUserPowerLevel(targetUserID)
			return senderPL > targetPL
		}

		return true

	case "m.room.power_levels":
		// To alter power levels, the sender must meet or exceed the current requirement (default 100)
		reqPL := int64(100)
		if plEvent != nil {
			var content struct {
				StateDefault int64            `json:"state_default"`
				Events       map[string]int64 `json:"events"`
			}
			if err := json.Unmarshal(plEvent.Content, &content); err == nil {
				if pl, ok := content.Events["m.room.power_levels"]; ok {
					reqPL = pl
				} else if content.StateDefault > 0 {
					reqPL = content.StateDefault
				}
			}
		}
		return senderPL >= reqPL

	default:
		// For normal state events (m.room.name, m.room.topic, m.room.canonical_alias, etc.):
		// Requirement A: Sender MUST be actively joined to the room in currentState
		memberEv := getStateEvent("m.room.member", ev.Sender)
		if memberEv == nil {
			return false
		}
		var memberContent struct {
			Membership string `json:"membership"`
		}
		if err := json.Unmarshal(memberEv.Content, &memberContent); err != nil || memberContent.Membership != "join" {
			return false
		}

		// Requirement B: Sender MUST have effective PL >= required PL for this event type
		reqPL := int64(50) // Matrix standard default for state events is 50
		if plEvent != nil {
			var plContent struct {
				StateDefault int64            `json:"state_default"`
				Events       map[string]int64 `json:"events"`
			}
			if err := json.Unmarshal(plEvent.Content, &plContent); err == nil {
				if pl, ok := plContent.Events[ev.Tipo]; ok {
					reqPL = pl
				} else if plContent.StateDefault != 0 {
					reqPL = plContent.StateDefault
				}
			}
		}
		return senderPL >= reqPL
	}
}
