package onepass

import (
	"errors"
)

var (
	ErrLocked          = errors.New("vault is locked")
	ErrInvalidPassword = errors.New("invalid password")
	ErrNoSecurityLevel = errors.New("security level not found")
)

type Vault interface {
	// Lock() removes previously loaded encrypted keys from memory.
	Lock() error

	// Unlock() attempts to decrypt the vault and store its encryption
	// keys in memory for future use.
	Unlock(masterPassword []byte) error
}
