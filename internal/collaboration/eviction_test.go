package collaboration

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/mohitbadwal/team-relay/internal/protocol"
	"github.com/redis/go-redis/v9"
)

func TestRevocationEvictsPresenceAndPermanentlyClosesAgentStreams(t *testing.T) {
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewRedisStore(rdb)
	hub := NewHub()
	evicter := NewRevocationEvicter(store, hub)
	requester := devicePrincipal("org_1", "mem_1", "dev_1", "agent_1", "Requester", "codex", protocol.PermissionReadOnly)
	target := devicePrincipal("org_1", "mem_2", "dev_2", "agent_2", "Target", "claude-code", protocol.PermissionReadOnly)
	heartbeat := protocol.AgentHeartbeat{
		DisplayName: "Target", Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
		Runtime:        protocol.RuntimeDescriptor{ID: "claude-code", DisplayName: "Claude Code"},
		PermissionMode: protocol.PermissionReadOnly,
	}
	if _, err := store.Heartbeat(context.Background(), target, heartbeat); err != nil {
		t.Fatal(err)
	}
	stream, unsubscribe := hub.Subscribe(target.OrganizationID, target.AgentID)
	defer unsubscribe()
	if err := evicter.EvictRevokedAgents(context.Background(), target.OrganizationID, []string{target.AgentID}); err != nil {
		t.Fatal(err)
	}
	if _, open := <-stream; open {
		t.Fatal("active subscriber remained open after revocation")
	}
	lateStream, lateUnsubscribe := hub.Subscribe(target.OrganizationID, target.AgentID)
	defer lateUnsubscribe()
	if _, open := <-lateStream; open {
		t.Fatal("stale authenticated request attached a stream after revocation")
	}
	if _, err := store.Heartbeat(context.Background(), target, heartbeat); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked agent heartbeat error = %v", err)
	}
	if _, err := store.Inbox(context.Background(), target); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked agent inbox error = %v", err)
	}
	directory, err := store.ListAgents(context.Background(), requester, AgentQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(directory.Agents) != 0 {
		t.Fatalf("revoked target remained in directory: %#v", directory.Agents)
	}
	listed, err := rdb.SIsMember(context.Background(), agentsKey(target.OrganizationID), target.AgentID).Result()
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := rdb.SIsMember(context.Background(), revokedAgentsKey(target.OrganizationID), target.AgentID).Result()
	if err != nil {
		t.Fatal(err)
	}
	if mini.Exists(agentKey(target.OrganizationID, target.AgentID)) || listed || !revoked {
		t.Fatal("presence keys did not reflect permanent agent eviction")
	}
}

func TestHeartbeatRaceCannotRestoreEvictedPresence(t *testing.T) {
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewRedisStore(rdb)
	target := devicePrincipal("org_1", "mem_2", "dev_2", "agent_2", "Target", "claude-code", protocol.PermissionReadOnly)
	heartbeat := protocol.AgentHeartbeat{
		DisplayName: "Target", Availability: protocol.AvailabilityAvailable, AcceptingRequests: true,
		Runtime:        protocol.RuntimeDescriptor{ID: "claude-code", DisplayName: "Claude Code"},
		PermissionMode: protocol.PermissionReadOnly,
	}
	if _, err := store.Heartbeat(context.Background(), target, heartbeat); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for range 25 {
				_, _ = store.Heartbeat(context.Background(), target, heartbeat)
			}
		}()
	}
	close(start)
	if err := NewRevocationEvicter(store, NewHub()).EvictRevokedAgents(context.Background(), target.OrganizationID, []string{target.AgentID}); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if mini.Exists(agentKey(target.OrganizationID, target.AgentID)) {
		t.Fatal("an in-flight heartbeat restored presence after eviction")
	}
	if _, err := store.Heartbeat(context.Background(), target, heartbeat); !errors.Is(err, ErrForbidden) {
		t.Fatalf("post-eviction heartbeat error = %v", err)
	}
}
