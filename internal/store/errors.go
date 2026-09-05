package store

import "errors"

var (
	ErrAlreadyBootstrapped = errors.New("relay is already bootstrapped")
	ErrNotBootstrapped     = errors.New("relay is not bootstrapped")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrForbidden           = errors.New("forbidden")
	ErrNotFound            = errors.New("not found")
	ErrConflict            = errors.New("conflict")
	ErrInviteExpired       = errors.New("invite expired")
	ErrInviteUsed          = errors.New("invite already used")
	ErrInviteRevoked       = errors.New("invite revoked")
	ErrInvalid             = errors.New("invalid input")
)
