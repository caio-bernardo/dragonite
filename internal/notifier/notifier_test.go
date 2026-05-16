package notifier

import (
	"testing"
)

func TestMainMemoryNotifier(t *testing.T) {

	t.Run("test can subscribe user once", func(t *testing.T) {
		notifier := NewInMemoryNotifier()
		fakeUser := "@fake:server.com"

		ch := notifier.Subscribe(fakeUser)
		defer notifier.Unsubscribe(fakeUser, ch)

		if ch == nil {
			t.Error("Subscribe should return a non-nil channel")
		}
	})

	t.Run("test can subscribe many users", func(t *testing.T) {
		notifier := NewInMemoryNotifier()
		users := []string{"@user1:server.com", "@user2:server.com", "@user3:server.com"}
		channels := make(map[string][]chan struct{})

		// Subscribe each user multiple times
		for _, user := range users {
			for range 3 {
				ch := notifier.Subscribe(user)
				channels[user] = append(channels[user], ch)
			}
		}

		// Verify all channels are created
		for user, chans := range channels {
			if len(chans) != 3 {
				t.Errorf("Expected 3 channels for user %s, got %d", user, len(chans))
			}
			for _, ch := range chans {
				defer notifier.Unsubscribe(user, ch)
			}
		}
	})

	t.Run("test can notify many users with many channels", func(t *testing.T) {
		notifier := NewInMemoryNotifier()
		users := []string{"@user1:server.com", "@user2:server.com"}
		channels := make(map[string][]chan struct{})

		// Subscribe each user with multiple channels
		for _, user := range users {
			for range 2 {
				ch := notifier.Subscribe(user)
				channels[user] = append(channels[user], ch)
			}
		}

		// Notify a user and verify all their channels receive the notification
		testUser := users[0]
		notifier.Notify(testUser)

		for _, ch := range channels[testUser] {
			select {
			case <-ch:
				// Notification received as expected
			default:
				t.Error("Expected notification on channel")
			}
			defer notifier.Unsubscribe(testUser, ch)
		}

		// Verify other user's channels were not notified
		for _, ch := range channels[users[1]] {
			select {
			case <-ch:
				t.Error("Should not receive notification for other user")
			default:
				// Expected behavior
			}
			defer notifier.Unsubscribe(users[1], ch)
		}
	})
}
