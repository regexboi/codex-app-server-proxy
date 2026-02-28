package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/mishca/codex-app-server-proxy/internal/config"
)

type Principal struct {
	KeyID string
	Role  string
}

type Authenticator struct {
	keys []storedKey
}

type storedKey struct {
	id       string
	role     string
	hashHex  string
	hashByte []byte
}

func NewAuthenticator(cfgKeys []config.APIKey) (*Authenticator, error) {
	keys := make([]storedKey, 0, len(cfgKeys))
	for _, key := range cfgKeys {
		normHash := normalizeHash(key.Hash)
		hashBytes, err := hex.DecodeString(normHash)
		if err != nil {
			return nil, errors.New("api key hash must be hex sha256")
		}
		if len(hashBytes) != sha256.Size {
			return nil, errors.New("api key hash must be a sha256 digest")
		}
		keys = append(keys, storedKey{
			id:       key.ID,
			role:     key.Role,
			hashHex:  normHash,
			hashByte: hashBytes,
		})
	}
	return &Authenticator{keys: keys}, nil
}

func (a *Authenticator) AuthenticateHeader(authHeader string) (Principal, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return Principal{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
	if token == "" {
		return Principal{}, false
	}
	return a.AuthenticateToken(token)
}

func (a *Authenticator) AuthenticateToken(token string) (Principal, bool) {
	sum := sha256.Sum256([]byte(token))
	matched := false
	principal := Principal{}

	for _, key := range a.keys {
		cmp := subtle.ConstantTimeCompare(sum[:], key.hashByte)
		if cmp == 1 {
			matched = true
			principal = Principal{KeyID: key.id, Role: key.role}
		}
	}
	return principal, matched
}

func normalizeHash(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "sha256:")
	return v
}
