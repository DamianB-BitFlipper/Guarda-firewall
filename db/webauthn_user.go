package db

import (
	"encoding/binary"

	"webauthn/webauthn"
)

// Webauthn is public key of a user.
type webauthnUser struct {
	userID      int64
	username    string
	credentials []webauthn.Credential
}

// Make sure `webauthnUser` implements the `webauthn.User` interface
var _ webauthn.User = webauthnUser{}

func (w webauthnUser) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)

	// This application does not keep track of `userID`s,
	// accessing occurs via `username`
	binary.PutUvarint(buf, uint64(0))

	return buf
}

func (w webauthnUser) WebAuthnName() string {
	return w.username
}

func (w webauthnUser) WebAuthnDisplayName() string {
	return w.username
}

func (w webauthnUser) WebAuthnIcon() string {
	return ""
}

func (w webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return w.credentials
}
