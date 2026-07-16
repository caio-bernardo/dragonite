package postgres

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresNotifier struct {
	db          *pgxpool.Pool
	mu          sync.RWMutex
	subscribers map[string][]chan struct{}
}

func NewPostgresNotifier(db *pgxpool.Pool) *PostgresNotifier {
	return &PostgresNotifier{db: db, subscribers: make(map[string][]chan struct{})}
}

// StartBackgroundListener starts a background listener for matrix_sync_client notifications.
func (p *PostgresNotifier) StartBackgroundListener(ctx context.Context) error {
	conn, err := p.db.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("Failed to acquire connection: %w", err)
	}
	defer conn.Release()

	_, err = conn.Exec(ctx, "LISTEN matrix_room_sync_client")
	if err != nil {
		return fmt.Errorf("Failed to execute LISTEN: %w", err)
	}

	for {
		notif, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Println("Error waiting for notification: %w", err)
			continue
		}

		// TODO: considerar eventos de accountData e presence. Mas fazer isso depois
		// notifica todos os usuario que estão no canal em que o evento ocorreu
		roomID := notif.Payload
		rows, err := conn.Query(ctx, "SELECT id_usuario FROM Canal_Membership WHERE id_canal = $1 AND membership_type IN ('join', 'invite')", roomID)
		if err != nil {
			log.Println("Error querying Canal_Membership: %w", err)
			continue
		}
		for rows.Next() {
			var userID string
			if err := rows.Scan(&userID); err != nil {
				log.Println("Error scanning user ID: %w", err)
				continue
			}
			p.WakeUpUsers(userID)
		}
		if err := rows.Err(); err != nil {
			log.Println("Error iterating over users: %w", err)
		}
		rows.Close()
	}
}

// WakeUpUsers wakes up all subscribers for a given user ID.
func (p *PostgresNotifier) WakeUpUsers(userID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	channels, exists := p.subscribers[userID]
	if !exists {
		return // No active /sync requests for this user right now
	}

	for _, ch := range channels {
		// Non-blocking send in case the channel is already buffered/closed
		select {
		case ch <- struct{}{}:
		default:
		}
	}

	// Clear the subscribers since they have been notified and will return to HTTP client
	delete(p.subscribers, userID)
}

// WaitForEvents implements the Notifier interface from our SyncService
func (p *PostgresNotifier) WaitForEvents(ctx context.Context, userID string) error {
	// Create a buffered channel to prevent blocking the background listener
	ch := make(chan struct{}, 1)

	// Safely register this channel for the given userID
	p.mu.Lock()
	p.subscribers[userID] = append(p.subscribers[userID], ch)
	p.mu.Unlock()

	// Ensure cleanup happens when this function exits (due to timeout or event)
	defer func() {
		p.mu.Lock()
		defer p.mu.Unlock()

		subs := p.subscribers[userID]
		for i, sub := range subs {
			if sub == ch {
				// Remove our channel from the slice efficiently
				p.subscribers[userID] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		// Clean up the map key if empty to avoid memory leaks
		if len(p.subscribers[userID]) == 0 {
			delete(p.subscribers, userID)
		}
	}()

	// Block until an event arrives OR the context times out
	select {
	case <-ch:
		return nil // Woken up by Postgres NOTIFY!
	case <-ctx.Done():
		return ctx.Err() // Woken up by context timeout (Long-polling finished)
	}
}
