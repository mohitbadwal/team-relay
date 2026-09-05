package runtime

import "testing"

func TestApprovalConfigFingerprintCanonicalizesNestedJSONAndHidesInput(t *testing.T) {
	left := struct {
		Servers map[string]any `json:"servers"`
	}{Servers: map[string]any{"private": map[string]any{"token": "credential-sentinel", "url": "https://example.test"}}}
	right := map[string]any{"servers": map[string]any{"private": map[string]any{"url": "https://example.test", "token": "credential-sentinel"}}}

	leftDigest, err := ApprovalConfigFingerprint(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := ApprovalConfigFingerprint(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("semantically identical configurations differ: %q != %q", leftDigest, rightDigest)
	}
	if leftDigest == "" || leftDigest == "credential-sentinel" {
		t.Fatalf("fingerprint exposed or omitted private configuration: %q", leftDigest)
	}
}

func TestCanonicalEnvironmentAllowlistUsesSetSemantics(t *testing.T) {
	got := CanonicalEnvironmentAllowlist([]string{" token ", "PATH", "TOKEN", "TEAM_RELAY_DEVICE_TOKEN"})
	if len(got) != 2 || got[0] != "PATH" || got[1] != "TOKEN" {
		t.Fatalf("canonical allowlist = %#v", got)
	}
}
