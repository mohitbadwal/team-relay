// Package keyspace owns Redis key names shared across otherwise independent
// server packages. Keeping these keys here prevents administrative revocation
// and collaboration authorization from silently drifting to different keys.
package keyspace

import "encoding/hex"

const collaborationPrefix = "team-relay:v1:collab:"

// CollaborationRevokedAgents is the permanent tombstone set for random agent
// IDs revoked inside one organization.
func CollaborationRevokedAgents(organizationID string) string {
	return collaborationPrefix + hex.EncodeToString([]byte(organizationID)) + ":revoked-agents"
}
