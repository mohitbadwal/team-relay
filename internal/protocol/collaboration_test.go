package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPermissionModes(t *testing.T) {
	t.Parallel()

	for _, mode := range []PermissionMode{PermissionReadOnly, PermissionGuardedWrite, PermissionCustom} {
		if !mode.Valid() {
			t.Fatalf("expected %q to be valid", mode)
		}
	}
	if PermissionMode("full_remote_control").Valid() {
		t.Fatal("unknown permission mode must be rejected")
	}
}

func TestTerminalStatuses(t *testing.T) {
	t.Parallel()

	if StatusRunning.Terminal() {
		t.Fatal("running must not be terminal")
	}
	if !StatusCompleted.Terminal() || !StatusRejected.Terminal() {
		t.Fatal("completed and rejected must be terminal")
	}
}

func TestRequesterMemberIdentityIsAdditiveAndOptional(t *testing.T) {
	t.Parallel()

	legacy, err := json.Marshal(RequestNotice{RequesterAgentID: "agent_legacy"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(legacy, []byte("requester_member_id")) {
		t.Fatalf("legacy notice encoded an empty requester member identity: %s", legacy)
	}

	current, err := json.Marshal(RequestNotice{
		RequesterAgentID:  "agent_current",
		RequesterMemberID: "mem_authenticated",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(current, []byte(`"requester_member_id":"mem_authenticated"`)) {
		t.Fatalf("notice omitted the authenticated requester member identity: %s", current)
	}

	var decoded RequestNotice
	if err := json.Unmarshal(legacy, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RequesterMemberID != "" {
		t.Fatalf("legacy notice decoded requester member identity %q", decoded.RequesterMemberID)
	}
}
