package main

import (
	"encoding/json"
	"net/http"
	"testing"

	appconfig "github.com/mohitbadwal/team-relay/internal/config"
	"github.com/mohitbadwal/team-relay/internal/receiver"
)

func TestControlRequestTargetInspect(t *testing.T) {
	method, endpoint, body, err := controlRequestTarget(options{command: "inspect", commandArgs: []string{" req/1 "}})
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodGet || endpoint != "/v1/requests/req%2F1/proposal" || len(body) != 0 {
		t.Fatalf("inspect target = %s %s", method, endpoint)
	}
}

func TestControlRequestTargetRequiresInspectRequestID(t *testing.T) {
	if _, _, _, err := controlRequestTarget(options{command: "inspect"}); err == nil {
		t.Fatal("inspect without a request ID was accepted")
	}
}

func TestControlRequestTargetsStandingApprovals(t *testing.T) {
	method, endpoint, body, err := controlRequestTarget(options{
		command: "approve", commandArgs: []string{" req/1 ", "conversation_30m"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]receiver.ApprovalLevel
	if err := json.Unmarshal(body, &input); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || endpoint != "/v1/requests/req%2F1/approve" || input["level"] != receiver.ApprovalLevelConversation30m {
		t.Fatalf("approve target = %s %s %s", method, endpoint, body)
	}

	method, endpoint, body, err = controlRequestTarget(options{command: "approval-grants"})
	if err != nil || method != http.MethodGet || endpoint != "/v1/approval-grants" || len(body) != 0 {
		t.Fatalf("list target = %s %s %s err=%v", method, endpoint, body, err)
	}
	method, endpoint, body, err = controlRequestTarget(options{command: "revoke-approval-grant", commandArgs: []string{"grant/1"}})
	if err != nil || method != http.MethodDelete || endpoint != "/v1/approval-grants/grant%2F1" || len(body) != 0 {
		t.Fatalf("revoke target = %s %s %s err=%v", method, endpoint, body, err)
	}
	if _, _, _, err := controlRequestTarget(options{command: "approve", commandArgs: []string{"req", "invalid"}}); err == nil {
		t.Fatal("invalid approval level was accepted")
	}
}

func TestApprovalAuthorityFingerprintChangesWithCredentialOrPolicy(t *testing.T) {
	allowWrites := false
	config := appconfig.Config{
		Version:  1,
		Relay:    appconfig.RelayConfig{URL: "https://relay.example.test"},
		Receiver: appconfig.ReceiverConfig{Profile: "default", MaxConcurrent: 1, RuntimeSecs: 900},
		Profiles: map[string]appconfig.ReceiverProfile{
			"default": {Runtime: "claude", Policy: appconfig.PolicyConfig{Mode: "read_only", AllowWrites: &allowWrites}},
		},
		Workspaces: map[string]string{"repo": "/work/repo"},
	}
	first, err := approvalAuthorityFingerprint(config, "token-one")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := approvalAuthorityFingerprint(config, "token-two")
	if first == second {
		t.Fatal("credential change did not invalidate approval authority")
	}
	config.Profiles["default"] = appconfig.ReceiverProfile{Runtime: "claude", Policy: appconfig.PolicyConfig{Mode: "guarded_write"}}
	third, _ := approvalAuthorityFingerprint(config, "token-one")
	if first == third {
		t.Fatal("receiver policy change did not invalidate approval authority")
	}
}
