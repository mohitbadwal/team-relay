package receiver

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	appconfig "github.com/mohitbadwal/team-relay/internal/config"
	"github.com/mohitbadwal/team-relay/internal/privatefs"
	relayruntime "github.com/mohitbadwal/team-relay/internal/runtime"
)

type fakeAdapter struct {
	mu           sync.Mutex
	policy       relayruntime.Policy
	workDir      string
	approval     string
	capabilities *relayruntime.Capabilities
	seen         relayruntime.RunRequest
	result       relayruntime.RunResult
	runGate      chan struct{}
	onRun        func()
	onRequest    func(relayruntime.RunRequest)
}

func (f *fakeAdapter) ID() string                            { return "fake" }
func (f *fakeAdapter) ConfiguredPolicy() relayruntime.Policy { return f.policy }
func (f *fakeAdapter) WorkDirFingerprint() string {
	workDir := f.workDir
	if workDir == "" {
		workDir = "/fake/team-relay-workdir"
	}
	return relayruntime.WorkDirFingerprint(workDir)
}
func (f *fakeAdapter) ApprovalFingerprint() (string, error) {
	if f.approval != "" {
		return f.approval, nil
	}
	return "fake-runtime-approval-fingerprint", nil
}
func (f *fakeAdapter) Probe(context.Context) (relayruntime.Capabilities, error) {
	if f.capabilities != nil {
		return *f.capabilities, nil
	}
	return relayruntime.Capabilities{RuntimeID: "fake", Available: true, Policy: relayruntime.PolicyCapabilities{
		ReadOnly:               relayruntime.EnforcementNative,
		GuardedWrite:           relayruntime.EnforcementNative,
		FilesystemIsolation:    relayruntime.EnforcementNative,
		NetworkIsolation:       relayruntime.EnforcementNative,
		ShellControl:           relayruntime.EnforcementNative,
		MCPControl:             relayruntime.EnforcementNative,
		DestructiveCommandDeny: relayruntime.EnforcementNative,
	}}, nil
}

func TestControllerProbeRejectsUnsupportedConfiguredPolicy(t *testing.T) {
	t.Parallel()
	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	capabilities := relayruntime.Capabilities{RuntimeID: "codex-like", Available: true, Policy: relayruntime.PolicyCapabilities{
		ReadOnly:               relayruntime.EnforcementNative,
		GuardedWrite:           relayruntime.EnforcementNative,
		FilesystemIsolation:    relayruntime.EnforcementBestEffort,
		NetworkIsolation:       relayruntime.EnforcementNative,
		ShellControl:           relayruntime.EnforcementUnsupported,
		MCPControl:             relayruntime.EnforcementToolLevel,
		DestructiveCommandDeny: relayruntime.EnforcementBestEffort,
	}}
	controller, err := NewController(&fakeAdapter{policy: policy, capabilities: &capabilities}, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Probe(context.Background()); err == nil || !strings.Contains(err.Error(), "shell control") {
		t.Fatalf("probe error = %v, want unsupported shell-control policy", err)
	}
}
func (f *fakeAdapter) Run(ctx context.Context, request relayruntime.RunRequest, _ relayruntime.EventSink) (relayruntime.RunResult, error) {
	if f.runGate != nil {
		select {
		case <-ctx.Done():
			return relayruntime.RunResult{}, ctx.Err()
		case <-f.runGate:
		}
	}
	f.mu.Lock()
	f.seen = request
	f.mu.Unlock()
	if f.onRun != nil {
		f.onRun()
	}
	if f.onRequest != nil {
		f.onRequest(request)
	}
	return f.result, nil
}

func TestControllerOwnsSessionAffinityAndIgnoresInjectedSession(t *testing.T) {
	store, err := NewFileSessionStore(filepath.Join(t.TempDir(), "state", "sessions.json"))
	if err != nil {
		t.Fatal(err)
	}
	legitimate := relayruntime.SessionRef{RuntimeID: "fake", OpaqueID: "local-session", PolicyFingerprint: "p", WorkDirFingerprint: "w"}
	if err := store.Put("conv_1", legitimate); err != nil {
		t.Fatal(err)
	}
	updated := &relayruntime.SessionRef{RuntimeID: "fake", OpaqueID: "updated-session", PolicyFingerprint: "p2", WorkDirFingerprint: "w2"}
	adapter := &fakeAdapter{result: relayruntime.RunResult{FinalText: "done", Session: updated}}
	controller, err := NewController(adapter, store, 1)
	if err != nil {
		t.Fatal(err)
	}
	request := relayruntime.RunRequest{
		RequestID:      "req_1",
		ConversationID: "conv_1",
		Prompt:         "help",
		Session:        &relayruntime.SessionRef{RuntimeID: "fake", OpaqueID: "peer-injected"},
	}
	if _, err := controller.Execute(context.Background(), request, nil); err != nil {
		t.Fatal(err)
	}
	adapter.mu.Lock()
	seen := adapter.seen.Session
	adapter.mu.Unlock()
	if seen == nil || seen.OpaqueID != "local-session" {
		t.Fatalf("controller passed peer-injected session: %#v", seen)
	}
	persisted, err := store.Get("conv_1")
	if err != nil {
		t.Fatal(err)
	}
	if persisted == nil || persisted.OpaqueID != "updated-session" {
		t.Fatalf("updated affinity was not persisted: %#v", persisted)
	}
}

func TestConversationLocksSerializeAndDeleteOnlyAfterLastReference(t *testing.T) {
	t.Parallel()

	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	controller, err := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 3)
	if err != nil {
		t.Fatal(err)
	}

	releaseFirst, err := controller.lockConversation(context.Background(), "conv_serial")
	if err != nil {
		t.Fatal(err)
	}
	controller.locksMu.Lock()
	original := controller.locks["conv_serial"]
	controller.locksMu.Unlock()

	secondAcquired := make(chan func(), 1)
	go func() {
		release, lockErr := controller.lockConversation(context.Background(), "conv_serial")
		if lockErr == nil {
			secondAcquired <- release
		}
	}()
	waitForConversationRefs(t, controller, "conv_serial", 2)
	select {
	case <-secondAcquired:
		t.Fatal("same-conversation waiter acquired before the holder released")
	default:
	}

	releaseFirst()
	var releaseSecond func()
	select {
	case releaseSecond = <-secondAcquired:
	case <-time.After(time.Second):
		t.Fatal("second same-conversation caller did not acquire")
	}
	controller.locksMu.Lock()
	if controller.locks["conv_serial"] != original || original.refs != 1 {
		controller.locksMu.Unlock()
		t.Fatal("conversation lock was deleted or replaced while still held")
	}
	controller.locksMu.Unlock()

	thirdAcquired := make(chan func(), 1)
	go func() {
		release, lockErr := controller.lockConversation(context.Background(), "conv_serial")
		if lockErr == nil {
			thirdAcquired <- release
		}
	}()
	waitForConversationRefs(t, controller, "conv_serial", 2)
	releaseSecond()
	var releaseThird func()
	select {
	case releaseThird = <-thirdAcquired:
	case <-time.After(time.Second):
		t.Fatal("third same-conversation caller did not acquire")
	}
	controller.locksMu.Lock()
	if controller.locks["conv_serial"] != original || original.refs != 1 {
		controller.locksMu.Unlock()
		t.Fatal("conversation lock was prematurely deleted between waiters")
	}
	controller.locksMu.Unlock()

	releaseThird()
	controller.locksMu.Lock()
	defer controller.locksMu.Unlock()
	if _, exists := controller.locks["conv_serial"]; exists || len(controller.locks) != 0 {
		t.Fatalf("unused conversation lock was retained: %#v", controller.locks)
	}
}

func TestCancelledConversationLockWaiterReleasesReference(t *testing.T) {
	t.Parallel()

	policy, _ := relayruntime.DefaultPolicy(relayruntime.PolicyReadOnly)
	controller, err := NewController(&fakeAdapter{policy: policy}, mustSessionStore(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	release, err := controller.lockConversation(context.Background(), "conv_cancel")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	waitDone := make(chan error, 1)
	go func() {
		_, lockErr := controller.lockConversation(ctx, "conv_cancel")
		waitDone <- lockErr
	}()
	waitForConversationRefs(t, controller, "conv_cancel", 2)
	cancel()
	select {
	case err := <-waitDone:
		if err != context.Canceled {
			t.Fatalf("cancelled waiter error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled waiter did not return")
	}
	waitForConversationRefs(t, controller, "conv_cancel", 1)
	release()
	controller.locksMu.Lock()
	defer controller.locksMu.Unlock()
	if len(controller.locks) != 0 {
		t.Fatalf("conversation lock leaked after cancellation: %#v", controller.locks)
	}
}

func waitForConversationRefs(t *testing.T, controller *Controller, conversationID string, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		controller.locksMu.Lock()
		lock := controller.locks[conversationID]
		got := 0
		if lock != nil {
			got = lock.refs
		}
		controller.locksMu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("conversation %q did not reach %d references", conversationID, want)
}

func TestFileSessionStorePersistsPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "sessions.json")
	store, err := NewFileSessionStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := relayruntime.SessionRef{RuntimeID: "codex", OpaqueID: "opaque", PolicyFingerprint: "policy", WorkDirFingerprint: "dir"}
	if err := store.Put("conv", want); err != nil {
		t.Fatal(err)
	}
	if err := privatefs.ValidateRegularFile(path); err != nil {
		t.Fatalf("session store is not private: %v", err)
	}
	if err := privatefs.ValidateDirectory(filepath.Dir(path)); err != nil {
		t.Fatalf("session store directory is not private: %v", err)
	}
	reloaded, err := NewFileSessionStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reloaded.Get("conv")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got != want {
		t.Fatalf("reloaded session = %#v, want %#v", got, want)
	}
	if err := reloaded.Delete("conv"); err != nil {
		t.Fatal(err)
	}
	got, err = reloaded.Get("conv")
	if err != nil || got != nil {
		t.Fatalf("deleted session = %#v, err = %v", got, err)
	}
}

func TestProfilePolicyUsesSafeDefaultsAndExplicitGuardedMode(t *testing.T) {
	readOnly, err := policyFromProfile(appconfig.ReceiverProfile{Policy: appconfig.PolicyConfig{Mode: string(relayruntime.PolicyReadOnly)}})
	if err != nil {
		t.Fatal(err)
	}
	if readOnly.AllowWrites || readOnly.AllowShell || readOnly.AllowMCPs || readOnly.AllowNetwork {
		t.Fatalf("unsafe read-only defaults: %#v", readOnly)
	}
	guarded, err := policyFromProfile(appconfig.ReceiverProfile{Policy: appconfig.PolicyConfig{Mode: string(relayruntime.PolicyGuardedWrite)}})
	if err != nil {
		t.Fatal(err)
	}
	if !guarded.AllowWrites || !guarded.AllowShell || !guarded.AllowMCPs || !guarded.AllowNetwork {
		t.Fatalf("guarded-write defaults are incomplete: %#v", guarded)
	}
}

func TestCustomProfileRequiresExplicitCapabilities(t *testing.T) {
	trueValue := true
	custom, err := policyFromProfile(appconfig.ReceiverProfile{Policy: appconfig.PolicyConfig{
		Mode: string(relayruntime.PolicyCustom), AllowWrites: &trueValue, AllowShell: &trueValue, AllowMCPs: &trueValue, Network: "allow",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !custom.AllowWrites || !custom.AllowShell || !custom.AllowMCPs || !custom.AllowNetwork {
		t.Fatalf("explicit custom policy was not applied: %#v", custom)
	}
	falseValue := false
	if _, err := policyFromProfile(appconfig.ReceiverProfile{Policy: appconfig.PolicyConfig{Mode: string(relayruntime.PolicyGuardedWrite), DenyNestedRelay: &falseValue}}); err == nil {
		t.Fatal("nested Team Relay was allowed by local configuration")
	}
}

func TestBuildControllerUsesCanonicalConfiguredRuntime(t *testing.T) {
	directory := t.TempDir()
	config := appconfig.Config{
		Receiver: appconfig.ReceiverConfig{Profile: "default", MaxConcurrent: 1, RuntimeSecs: 60},
		Profiles: map[string]appconfig.ReceiverProfile{
			"default": {Runtime: "codex", WorkDir: directory, Policy: appconfig.PolicyConfig{Mode: "read_only"}},
		},
	}
	controller, err := BuildController(config, filepath.Join(directory, "state", "sessions.json"))
	if err != nil {
		t.Fatal(err)
	}
	if controller.RuntimeID() != "codex" || controller.ConfiguredPolicy().Mode != relayruntime.PolicyReadOnly {
		t.Fatalf("unexpected controller configuration: runtime=%q policy=%#v", controller.RuntimeID(), controller.ConfiguredPolicy())
	}
	canonicalDirectory, err := relayruntime.ValidateWorkDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := controller.WorkDirFingerprint(), relayruntime.WorkDirFingerprint(canonicalDirectory); got != want {
		t.Fatalf("controller workdir fingerprint = %q, want %q", got, want)
	}
}
