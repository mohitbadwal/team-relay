package collaboration

import "testing"

func TestHubOverflowClosesSubscriberForDurableReconciliation(t *testing.T) {
	hub := NewHub()
	channel, unsubscribe := hub.Subscribe("org_1", "agent_1")
	defer unsubscribe()

	for index := 0; index < cap(channel); index++ {
		hub.Publish("org_1", "agent_1", event{Type: "peer_request"})
	}
	hub.Publish("org_1", "agent_1", event{Type: "peer_request"})

	hub.mu.RLock()
	remaining := len(hub.subscribers)
	hub.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("overflowed subscriber remained registered: %d keys", remaining)
	}

	for index := 0; index < cap(channel); index++ {
		if _, open := <-channel; !open {
			t.Fatalf("subscriber closed before buffered event %d was drained", index)
		}
	}
	if _, open := <-channel; open {
		t.Fatal("overflowed subscriber was not closed")
	}
}
