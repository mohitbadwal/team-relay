package collaboration

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/redis/go-redis/v9"
)

// RevocationEvicter bridges authoritative administration state into the
// collaboration presence and live-event layers.
type RevocationEvicter struct {
	store *RedisStore
	hub   *Hub
}

func NewRevocationEvicter(store *RedisStore, hub *Hub) *RevocationEvicter {
	return &RevocationEvicter{store: store, hub: hub}
}

func (e *RevocationEvicter) EvictRevokedAgents(ctx context.Context, organizationID string, agentIDs []string) error {
	if e == nil || e.store == nil || e.hub == nil {
		return errors.New("collaboration revocation eviction is unavailable")
	}
	ids := cleanAgentIDs(agentIDs)
	if strings.TrimSpace(organizationID) == "" || len(ids) == 0 {
		return nil
	}
	// Close local streams first; this remains effective even if Redis becomes
	// unavailable immediately after the authoritative credential revocation.
	for _, agentID := range ids {
		e.hub.Revoke(organizationID, agentID)
	}
	if err := e.store.evictPresence(ctx, organizationID, ids); err != nil {
		return fmt.Errorf("evict collaboration presence: %w", err)
	}
	return nil
}

func (s *RedisStore) evictPresence(ctx context.Context, organizationID string, agentIDs []string) error {
	_, err := s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		for _, agentID := range agentIDs {
			pipe.SAdd(ctx, revokedAgentsKey(organizationID), agentID)
			pipe.SRem(ctx, agentsKey(organizationID), agentID)
			pipe.Del(ctx, agentKey(organizationID, agentID))
		}
		return nil
	})
	return err
}

func cleanAgentIDs(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			unique[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
