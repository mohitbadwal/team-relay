package mcpserver

import (
	"context"
	"testing"

	"github.com/mohitbadwal/team-relay/internal/client"
	"github.com/mohitbadwal/team-relay/internal/protocol"
)

type fakeRelay struct {
	created protocol.CreateRequest
}

func (f *fakeRelay) ListAgents(context.Context, client.AgentQuery) (*protocol.AgentDirectoryResponse, error) {
	return &protocol.AgentDirectoryResponse{}, nil
}
func (f *fakeRelay) CreateRequest(_ context.Context, request protocol.CreateRequest) (*protocol.MutationResponse, error) {
	f.created = request
	return &protocol.MutationResponse{RequestID: "req_1", ConversationID: "conv_1", Status: protocol.StatusAwaitingApproval}, nil
}
func (f *fakeRelay) GetRequest(context.Context, string) (*protocol.Request, error) {
	return &protocol.Request{}, nil
}
func (f *fakeRelay) CancelRequest(context.Context, string) (*protocol.MutationResponse, error) {
	return &protocol.MutationResponse{}, nil
}
func (f *fakeRelay) FetchArtifact(context.Context, string) (*protocol.ArtifactContent, error) {
	return &protocol.ArtifactContent{}, nil
}

func TestBuildRequestRejectsCustomRemotePermission(t *testing.T) {
	t.Parallel()

	service := &Service{relay: &fakeRelay{}, attachments: &attachmentStore{roots: map[string]*attachmentWorkspace{}}}
	_, err := service.buildRequest("title", "prompt", []protocol.RequestedAccess{{WorkspaceAlias: "repo", Mode: protocol.PermissionCustom}}, nil, 60, "idem_1")
	if err == nil {
		t.Fatal("requester must not be able to request recipient custom policy")
	}
}
