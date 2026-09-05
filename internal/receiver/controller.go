// Package receiver coordinates one recipient-configured runtime with private
// session affinity and bounded concurrency.
package receiver

import (
	"context"
	"fmt"
	"sync"

	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

type Controller struct {
	adapter relayruntime.Adapter
	store   SessionStore
	sem     chan struct{}

	locksMu sync.Mutex
	locks   map[string]*conversationLock
}

type conversationLock struct {
	gate chan struct{}
	refs int
}

func NewController(adapter relayruntime.Adapter, store SessionStore, maxConcurrent int) (*Controller, error) {
	if adapter == nil {
		return nil, fmt.Errorf("runtime adapter is required")
	}
	if store == nil {
		return nil, fmt.Errorf("session store is required")
	}
	if maxConcurrent <= 0 {
		return nil, fmt.Errorf("max_concurrent must be positive")
	}
	return &Controller{
		adapter: adapter,
		store:   store,
		sem:     make(chan struct{}, maxConcurrent),
		locks:   make(map[string]*conversationLock),
	}, nil
}

func (c *Controller) RuntimeID() string { return c.adapter.ID() }

func (c *Controller) ConfiguredPolicy() relayruntime.Policy { return c.adapter.ConfiguredPolicy() }

func (c *Controller) WorkDirFingerprint() string { return c.adapter.WorkDirFingerprint() }

// RuntimeApprovalFingerprint binds standing approval authority to the exact
// recipient-owned runtime configuration and its frozen MCP inventory.
func (c *Controller) RuntimeApprovalFingerprint() (string, error) {
	return c.adapter.ApprovalFingerprint()
}

func (c *Controller) Probe(ctx context.Context) (relayruntime.Capabilities, error) {
	capabilities, err := c.adapter.Probe(ctx)
	if err != nil || !capabilities.Available {
		return capabilities, err
	}
	if err := relayruntime.ValidatePolicySupport(capabilities, c.adapter.ConfiguredPolicy()); err != nil {
		return capabilities, err
	}
	return capabilities, nil
}

func (c *Controller) ResumesConversation(conversationID string) (bool, error) {
	session, err := c.store.Get(conversationID)
	return session != nil, err
}

func (c *Controller) Execute(ctx context.Context, request relayruntime.RunRequest, sink relayruntime.EventSink) (relayruntime.RunResult, error) {
	if err := relayruntime.ValidateRunRequest(request); err != nil {
		return relayruntime.RunResult{}, err
	}
	release, err := c.lockConversation(ctx, request.ConversationID)
	if err != nil {
		return relayruntime.RunResult{}, err
	}
	defer release()

	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return relayruntime.RunResult{}, ctx.Err()
	}

	// Session affinity is private local state. Ignore any session reference in
	// the relay/request payload so a peer cannot inject or select a local session.
	stored, err := c.store.Get(request.ConversationID)
	if err != nil {
		return relayruntime.RunResult{}, fmt.Errorf("load local session affinity: %w", err)
	}
	request.Session = stored
	result, err := c.adapter.Run(ctx, request, sink)
	if err != nil {
		return relayruntime.RunResult{}, err
	}
	if result.Session == nil {
		if stored != nil {
			if err := c.store.Delete(request.ConversationID); err != nil {
				return relayruntime.RunResult{}, fmt.Errorf("remove stale local session affinity: %w", err)
			}
		}
		return result, nil
	}
	if result.Session.RuntimeID != c.adapter.ID() {
		return relayruntime.RunResult{}, fmt.Errorf("runtime returned session for %q, expected %q", result.Session.RuntimeID, c.adapter.ID())
	}
	if err := c.store.Put(request.ConversationID, *result.Session); err != nil {
		return relayruntime.RunResult{}, fmt.Errorf("persist local session affinity: %w", err)
	}
	return result, nil
}

func (c *Controller) lockConversation(ctx context.Context, conversationID string) (func(), error) {
	c.locksMu.Lock()
	lock, ok := c.locks[conversationID]
	if !ok {
		lock = &conversationLock{gate: make(chan struct{}, 1)}
		lock.gate <- struct{}{}
		c.locks[conversationID] = lock
	}
	// Count both the active holder and waiters before dropping locksMu. This
	// prevents a releasing holder from deleting the keyed lock while another
	// caller is about to acquire it.
	lock.refs++
	c.locksMu.Unlock()
	select {
	case <-ctx.Done():
		c.releaseConversationRef(conversationID, lock)
		return nil, ctx.Err()
	case <-lock.gate:
		if err := ctx.Err(); err != nil {
			lock.gate <- struct{}{}
			c.releaseConversationRef(conversationID, lock)
			return nil, err
		}
		var once sync.Once
		return func() {
			once.Do(func() {
				lock.gate <- struct{}{}
				c.releaseConversationRef(conversationID, lock)
			})
		}, nil
	}
}

func (c *Controller) releaseConversationRef(conversationID string, lock *conversationLock) {
	c.locksMu.Lock()
	defer c.locksMu.Unlock()
	lock.refs--
	if lock.refs == 0 && c.locks[conversationID] == lock {
		delete(c.locks, conversationID)
	}
}
