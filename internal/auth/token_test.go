package auth

import (
	"strings"
	"testing"
)

func TestTokenKindsAreDistinctAndWellFormed(t *testing.T) {
	kinds := []TokenKind{TokenBootstrap, TokenAdmin, TokenInvite, TokenDevice}
	seen := make(map[string]bool)
	for _, want := range kinds {
		token, err := NewToken(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Kind(token)
		if err != nil || got != want {
			t.Fatalf("Kind(%q) = %q, %v; want %q", token, got, err, want)
		}
		prefix := strings.SplitN(token, "_", 3)[:2]
		key := strings.Join(prefix, "_")
		if seen[key] {
			t.Fatalf("token prefix reused: %q", key)
		}
		seen[key] = true
	}
}

func TestHashAndConstantTimeComparison(t *testing.T) {
	token, err := NewToken(TokenDevice)
	if err != nil {
		t.Fatal(err)
	}
	if Hash(token) == token || len(Hash(token)) != 64 {
		t.Fatalf("unexpected token hash %q", Hash(token))
	}
	if !Equal(token, token) || Equal(token, token+"x") {
		t.Fatal("credential comparison returned an incorrect result")
	}
}
