package runtime

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePolicySupportRequiresEveryDeniedControl(t *testing.T) {
	t.Parallel()
	readOnly, _ := DefaultPolicy(PolicyReadOnly)
	complete := Capabilities{RuntimeID: "test", Policy: PolicyCapabilities{
		ReadOnly:               EnforcementNative,
		GuardedWrite:           EnforcementBestEffort,
		FilesystemIsolation:    EnforcementNative,
		NetworkIsolation:       EnforcementNative,
		ShellControl:           EnforcementToolLevel,
		MCPControl:             EnforcementToolLevel,
		DestructiveCommandDeny: EnforcementBestEffort,
	}}
	if err := ValidatePolicySupport(complete, readOnly); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name   string
		mutate func(*PolicyCapabilities)
	}{
		{name: "read-only", mutate: func(policy *PolicyCapabilities) { policy.ReadOnly = EnforcementUnsupported }},
		{name: "filesystem", mutate: func(policy *PolicyCapabilities) { policy.FilesystemIsolation = EnforcementUnsupported }},
		{name: "network", mutate: func(policy *PolicyCapabilities) { policy.NetworkIsolation = EnforcementUnsupported }},
		{name: "shell", mutate: func(policy *PolicyCapabilities) { policy.ShellControl = EnforcementUnsupported }},
		{name: "MCP", mutate: func(policy *PolicyCapabilities) { policy.MCPControl = EnforcementUnsupported }},
		{name: "destructive-command", mutate: func(policy *PolicyCapabilities) { policy.DestructiveCommandDeny = EnforcementUnsupported }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			capabilities := complete
			testCase.mutate(&capabilities.Policy)
			err := ValidatePolicySupport(capabilities, readOnly)
			if !errors.Is(err, ErrUnsupportedPolicy) || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(testCase.name)) {
				t.Fatalf("policy error = %v, want missing %s control", err, testCase.name)
			}
		})
	}
}

func TestValidatePolicySupportRequiresGuardedWriteWhenWritesAllowed(t *testing.T) {
	t.Parallel()
	guarded, _ := DefaultPolicy(PolicyGuardedWrite)
	capabilities := Capabilities{RuntimeID: "test", Policy: PolicyCapabilities{
		ReadOnly:               EnforcementNative,
		GuardedWrite:           EnforcementUnsupported,
		FilesystemIsolation:    EnforcementNative,
		NetworkIsolation:       EnforcementNative,
		ShellControl:           EnforcementNative,
		MCPControl:             EnforcementNative,
		DestructiveCommandDeny: EnforcementNative,
	}}
	if err := ValidatePolicySupport(capabilities, guarded); !errors.Is(err, ErrUnsupportedPolicy) || !strings.Contains(err.Error(), "guarded-write") {
		t.Fatalf("policy error = %v, want guarded-write failure", err)
	}
}
