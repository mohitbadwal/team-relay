package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

// TokenKind identifies a credential's authority. Token prefixes are deliberately
// different so an invite cannot accidentally be accepted as a device credential
// and a device credential cannot be used for administration.
type TokenKind string

const (
	TokenBootstrap TokenKind = "bootstrap"
	TokenAdmin     TokenKind = "admin"
	TokenInvite    TokenKind = "invite"
	TokenDevice    TokenKind = "device"
)

var ErrInvalidToken = errors.New("invalid token")

var tokenPrefixes = map[TokenKind]string{
	TokenBootstrap: "tr_boot_",
	TokenAdmin:     "tr_admin_",
	TokenInvite:    "tr_inv_",
	TokenDevice:    "tr_dev_",
}

// NewToken returns an opaque 256-bit credential. The raw value must be shown
// only once; callers should persist only Hash(token).
func NewToken(kind TokenKind) (string, error) {
	prefix, ok := tokenPrefixes[kind]
	if !ok {
		return "", ErrInvalidToken
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random), nil
}

func Kind(token string) (TokenKind, error) {
	token = strings.TrimSpace(token)
	for kind, prefix := range tokenPrefixes {
		if strings.HasPrefix(token, prefix) && len(token) == len(prefix)+64 {
			if _, err := hex.DecodeString(token[len(prefix):]); err == nil {
				return kind, nil
			}
		}
	}
	return "", ErrInvalidToken
}

// Hash is safe to store. It never stores or returns the original credential.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// Equal compares two raw credentials without leaking their common prefix.
func Equal(left, right string) bool {
	leftHash := sha256.Sum256([]byte(strings.TrimSpace(left)))
	rightHash := sha256.Sum256([]byte(strings.TrimSpace(right)))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}
