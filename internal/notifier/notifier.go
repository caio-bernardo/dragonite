package notifier

import "sync"

type Notifier interface {
	Subscribe(userId string) chan struct{}
	Unsubscribe(userId string, ch chan struct{})
	Notify(userID string)
}

// TODO: implement this in the future
type redisNotifier struct{}

type inMemoryNotifier struct {
	mu          sync.RWMutex
	subscribers map[string][]chan struct{}
}

func NewInMemoryNotifier() Notifier {
	return &inMemoryNotifier{
		subscribers: make(map[string][]chan struct{}),
	}
}

func (n *inMemoryNotifier) Subscribe(userID string) chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()

	// cria um novo canal de mensagens atrelado a um usuário
	ch := make(chan struct{}, 1)
	n.subscribers[userID] = append(n.subscribers[userID], ch)
	return ch
}

func (n *inMemoryNotifier) Unsubscribe(userID string, ch chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Apaga um canal relacionado a um usuário
	subs := n.subscribers[userID]
	for i, sub := range subs {
		if sub == ch {
			n.subscribers[userID] = append(subs[:i], subs[i+1:]...)
			break
		}
	}

	if len(n.subscribers[userID]) == 0 {
		delete(n.subscribers, userID)
	}
}

// Notifca um usuário
func (n *inMemoryNotifier) Notify(userID string) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	// notifica todos os canais do usuário
	subs, exists := n.subscribers[userID]
	if !exists {
		return
	}
	for _, sub := range subs {
		select {
		case sub <- struct{}{}:
		default:
		}
	}
}
