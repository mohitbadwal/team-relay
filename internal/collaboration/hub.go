package collaboration

import (
	"sync"
)

type event struct {
	Type    string
	Payload any
}

// Hub provides low-latency notifications for a single relay replica. Durable
// request state remains in Redis and is replayed through Inbox on reconnect.
type Hub struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan event]struct{}
	revoked     map[string]struct{}
}

func NewHub() *Hub {
	return &Hub{subscribers: make(map[string]map[chan event]struct{}), revoked: make(map[string]struct{})}
}

func (h *Hub) Subscribe(organizationID, agentID string) (<-chan event, func()) {
	key := organizationID + "\x00" + agentID
	channel := make(chan event, 32)
	h.mu.Lock()
	if _, isRevoked := h.revoked[key]; isRevoked {
		close(channel)
		h.mu.Unlock()
		return channel, func() {}
	}
	if h.subscribers[key] == nil {
		h.subscribers[key] = make(map[chan event]struct{})
	}
	h.subscribers[key][channel] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			h.mu.Lock()
			if _, exists := h.subscribers[key][channel]; !exists {
				h.mu.Unlock()
				return
			}
			delete(h.subscribers[key], channel)
			if len(h.subscribers[key]) == 0 {
				delete(h.subscribers, key)
			}
			close(channel)
			h.mu.Unlock()
		})
	}
	return channel, cancel
}

// Revoke permanently tombstones an agent ID for this process, detaches every
// active SSE subscriber, and prevents a request authenticated immediately
// before credential revocation from attaching a new stream afterward. Agent
// IDs are random and never reused by enrollment.
func (h *Hub) Revoke(organizationID, agentID string) {
	key := organizationID + "\x00" + agentID
	h.mu.Lock()
	defer h.mu.Unlock()
	h.revoked[key] = struct{}{}
	for channel := range h.subscribers[key] {
		close(channel)
	}
	delete(h.subscribers, key)
}

func (h *Hub) IsRevoked(organizationID, agentID string) bool {
	key := organizationID + "\x00" + agentID
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, revoked := h.revoked[key]
	return revoked
}

func (h *Hub) Publish(organizationID, agentID string, value event) {
	key := organizationID + "\x00" + agentID
	var overflowed []chan event
	h.mu.RLock()
	for channel := range h.subscribers[key] {
		select {
		case channel <- value:
		default:
			// A full subscriber cannot safely drop a notification while keeping
			// the stream alive: no later action necessarily forces a durable inbox
			// reconciliation. Detach and close it below so the receiver reconnects
			// and replays authoritative pending state.
			overflowed = append(overflowed, channel)
		}
	}
	h.mu.RUnlock()
	for _, channel := range overflowed {
		h.dropSubscriber(key, channel)
	}
}

func (h *Hub) dropSubscriber(key string, channel chan event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.subscribers[key][channel]; !exists {
		return
	}
	delete(h.subscribers[key], channel)
	if len(h.subscribers[key]) == 0 {
		delete(h.subscribers, key)
	}
	// Publishers hold RLock while sending, so closing under Lock cannot race
	// with an in-flight send.
	close(channel)
}
