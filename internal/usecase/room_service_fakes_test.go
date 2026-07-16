package usecase

import (
	"context"

	"github.com/caio-bernardo/dragonite/internal/domain"
	"github.com/caio-bernardo/dragonite/internal/domain/types"
)

// Fakes compartilhados entre room_membership_test.go e room_interaction_test.go

type roomsvcFakeWorkUnit struct{}

func (f *roomsvcFakeWorkUnit) Execute(ctx context.Context, fn func(txCtx context.Context) error) error {
	return fn(ctx)
}

type roomsvcUpsertMembershipCall struct {
	RoomID, UserID, Membership, EventID string
}

type roomsvcUpsertStateCall struct {
	RoomID, StateType, StateKey, EventID string
}

// roomsvcFakeCanalStorage implementa usecase.CanalStorage com comportamento configurável
type roomsvcFakeCanalStorage struct {
	membership    map[string]string // key: roomID+"|"+userID
	stateEventIDs map[string]string // key: roomID+"|"+type+"|"+stateKey -> eventID
	forwardExtrem map[string][]string
	joinRule      string
	joinedRooms   []string
	canal         *domain.Canal

	upsertedMemberships []roomsvcUpsertMembershipCall
	upsertedState       []roomsvcUpsertStateCall
}

func newRoomsvcFakeCanalStorage() *roomsvcFakeCanalStorage {
	return &roomsvcFakeCanalStorage{
		membership:    make(map[string]string),
		stateEventIDs: make(map[string]string),
		forwardExtrem: make(map[string][]string),
	}
}

func roomsvcMembershipKey(roomID, userID string) string { return roomID + "|" + userID }
func roomsvcStateKey(roomID, t, key string) string      { return roomID + "|" + t + "|" + key }

func (c *roomsvcFakeCanalStorage) Create(ctx context.Context, roomID, userID string) (*domain.Canal, error) {
	return &domain.Canal{ID: roomID, Criador: userID, Versao: "11"}, nil
}
func (c *roomsvcFakeCanalStorage) GetCanalParticipatingServers(ctx context.Context, canalID string) ([]string, error) {
	return nil, nil
}
func (c *roomsvcFakeCanalStorage) GetByID(ctx context.Context, canalID string) (*domain.Canal, error) {
	if c.canal != nil {
		return c.canal, nil
	}
	return &domain.Canal{ID: canalID, Versao: "11"}, nil
}
func (c *roomsvcFakeCanalStorage) GetJoinRule(ctx context.Context, roomID string) (string, error) {
	if c.joinRule == "" {
		return "invite", nil
	}
	return c.joinRule, nil
}
func (c *roomsvcFakeCanalStorage) GetUserJoinedRooms(ctx context.Context, userID string) ([]string, error) {
	return c.joinedRooms, nil
}
func (c *roomsvcFakeCanalStorage) GetUserLeftRooms(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}
func (c *roomsvcFakeCanalStorage) GetUserMembership(ctx context.Context, roomID, userID string) (string, error) {
	if m, ok := c.membership[roomsvcMembershipKey(roomID, userID)]; ok {
		return m, nil
	}
	return "leave", nil
}
func (c *roomsvcFakeCanalStorage) GetUserMembershipRecord(ctx context.Context, roomID, userID string) (string, bool, error) {
	if m, ok := c.membership[roomsvcMembershipKey(roomID, userID)]; ok {
		return m, true, nil
	}
	return "", false, nil
}
func (c *roomsvcFakeCanalStorage) GetStateEventID(ctx context.Context, canalID string, stateType, stateKeyStr string) (string, bool) {
	id, ok := c.stateEventIDs[roomsvcStateKey(canalID, stateType, stateKeyStr)]
	return id, ok
}
func (c *roomsvcFakeCanalStorage) UpsertMembership(ctx context.Context, roomID, userID, membership, id_evento string) error {
	c.upsertedMemberships = append(c.upsertedMemberships, roomsvcUpsertMembershipCall{roomID, userID, membership, id_evento})
	c.membership[roomsvcMembershipKey(roomID, userID)] = membership
	return nil
}
func (c *roomsvcFakeCanalStorage) UpsertCurrentState(ctx context.Context, canalID, stateType, stateKeyStr, eventID string) error {
	c.upsertedState = append(c.upsertedState, roomsvcUpsertStateCall{canalID, stateType, stateKeyStr, eventID})
	return nil
}
func (c *roomsvcFakeCanalStorage) GetAllPublic(ctx context.Context, offset, limit int) ([]domain.Canal, error) {
	return nil, nil
}
func (c *roomsvcFakeCanalStorage) UpdateForwardExtremities(ctx context.Context, canalID string, eventID string, prevEvents []string) error {
	c.forwardExtrem[canalID] = []string{eventID}
	return nil
}
func (c *roomsvcFakeCanalStorage) GetForwardExtremities(ctx context.Context, canalID string) ([]string, error) {
	return c.forwardExtrem[canalID], nil
}
func (c *roomsvcFakeCanalStorage) SaveAlias(ctx context.Context, roomID, fullAlias string) error {
	return nil
}

// roomsvcFakeEventoStorage implementa usecase.EventoStorage
type roomsvcFakeEventoStorage struct {
	events          map[string]domain.Evento
	saved           []domain.Evento
	messagesHistory []domain.Evento
}

func newRoomsvcFakeEventoStorage() *roomsvcFakeEventoStorage {
	return &roomsvcFakeEventoStorage{events: make(map[string]domain.Evento)}
}

func (e *roomsvcFakeEventoStorage) GetSince(ctx context.Context, userID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}
func (e *roomsvcFakeEventoStorage) GetMaxDepthFromEventos(ctx context.Context, eventIDs []string) (int64, error) {
	return 0, nil
}
func (e *roomsvcFakeEventoStorage) GetMaxStreamOrdering(ctx context.Context) (int64, error) {
	return 0, nil
}
func (e *roomsvcFakeEventoStorage) SaveEvento(ctx context.Context, event *domain.Evento) error {
	e.saved = append(e.saved, *event)
	e.events[event.ID] = *event
	return nil
}
func (e *roomsvcFakeEventoStorage) GetEvento(ctx context.Context, eventID string) (*domain.Evento, error) {
	if ev, ok := e.events[eventID]; ok {
		return &ev, nil
	}
	return nil, types.ErrNotFound
}
func (e *roomsvcFakeEventoStorage) GetEventsSince(ctx context.Context, roomID string, limit int, eventIDs []string) ([]domain.Evento, error) {
	return nil, nil
}
func (e *roomsvcFakeEventoStorage) GetEventsOfCanalSince(ctx context.Context, userID string, roomID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}
func (e *roomsvcFakeEventoStorage) CheckEventoExists(ctx context.Context, eventID string) (bool, error) {
	_, ok := e.events[eventID]
	return ok, nil
}
func (e *roomsvcFakeEventoStorage) GetCurrentStateEvents(ctx context.Context, roomID string) ([]domain.Evento, error) {
	return nil, nil
}
func (e *roomsvcFakeEventoStorage) GetStateAndAuthChainIDs(ctx context.Context, roomID string, eventID string) ([]string, []string, error) {
	return nil, nil, nil
}
func (e *roomsvcFakeEventoStorage) GetMissingEvents(ctx context.Context, roomID string, earliestEvents, latestEvents []string, limit int, minDepth int64) ([]domain.Evento, error) {
	return nil, nil
}
func (e *roomsvcFakeEventoStorage) SaveReceipt(ctx context.Context, userID, roomID, receiptType, eventID string, ts int64) error {
	return nil
}
func (e *roomsvcFakeEventoStorage) GetRoomMessagesHistory(ctx context.Context, roomID string, fromToken int64, dir string, limit int) ([]domain.Evento, error) {
	return e.messagesHistory, nil
}
func (e *roomsvcFakeEventoStorage) GetEventsOfCanalSinceLeft(ctx context.Context, userID string, roomID string, since domain.SyncToken) ([]domain.Evento, error) {
	return nil, nil
}
func (e *roomsvcFakeEventoStorage) GetStateAndAuthChainEvents(ctx context.Context, roomID string, userID string) ([]domain.Evento, []domain.Evento, error) {
	return nil, nil, nil
}
func (e *roomsvcFakeEventoStorage) GetRoomMemberEvents(ctx context.Context, roomID string) ([]domain.Evento, error) {
	return nil, nil
}
