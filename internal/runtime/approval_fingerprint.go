package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// ApprovalConfigFingerprint returns only a digest; potentially credential-
// bearing configuration is never exposed to callers. Marshaling and decoding
// once before the final encoding gives maps (including maps inside RawMessage
// values) a deterministic key order.
func ApprovalConfigFingerprint(configuration any) (string, error) {
	payload, err := json.Marshal(configuration)
	if err != nil {
		return "", errors.New("runtime approval configuration could not be encoded")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var canonical any
	if err := decoder.Decode(&canonical); err != nil {
		return "", errors.New("runtime approval configuration could not be canonicalized")
	}
	canonicalPayload, err := json.Marshal(canonical)
	if err != nil {
		return "", errors.New("runtime approval configuration could not be canonicalized")
	}
	digest := sha256.Sum256(canonicalPayload)
	return hex.EncodeToString(digest[:]), nil
}

// CanonicalEnvironmentAllowlist reflects SanitizedEnvironment semantics: names
// are case-insensitive, whitespace is ignored, and order does not matter.
func CanonicalEnvironmentAllowlist(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value != "" && !relayAuthorityVariable(value) {
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
