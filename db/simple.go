package db

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql/database"
	"go.step.sm/crypto/jose"
	"golang.org/x/crypto/ssh"
)

// ErrNotImplemented is an error returned when an operation is Not Implemented.
var ErrNotImplemented = errors.Errorf("not implemented")

// defaultUsedTokenRetention is the fallback retention period of a used token
// record when the validity of the token cannot be determined from the token
// itself.
const defaultUsedTokenRetention = 24 * time.Hour

// SimpleDB is a barebones implementation of the DB interface. It is NOT an
// in memory implementation of the DB, but rather the bare minimum of
// functionality that the CA requires to operate securely.
//
// When a data source is configured, used one-time tokens are persisted to a
// JSON file so that the protection against token reuse survives restarts of
// the process. Records expire with the validity of the token and are swept
// lazily, bounding the size of the file. Note that the file only provides
// persistence on a single host: deployments running multiple CA instances
// must configure a shared database instead, or each instance will keep its
// own records.
type SimpleDB struct {
	usedTokens *sync.Map
	// path is the location of the file used to persist used one-time
	// tokens. If empty, used tokens are only kept in memory.
	path string
	mu   sync.Mutex
}

func newSimpleDB(c *Config) (*SimpleDB, error) {
	db := &SimpleDB{
		usedTokens: new(sync.Map),
	}
	if c != nil && c.DataSource != "" {
		db.path = c.DataSource
		if err := db.loadUsedTokens(); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// IsRevoked noop
func (s *SimpleDB) IsRevoked(string) (bool, error) {
	return false, nil
}

// IsSSHRevoked noop
func (s *SimpleDB) IsSSHRevoked(string) (bool, error) {
	return false, nil
}

// Revoke returns a "NotImplemented" error.
func (s *SimpleDB) Revoke(*RevokedCertificateInfo) error {
	return ErrNotImplemented
}

// GetRevokedCertificates returns a "NotImplemented" error.
func (s *SimpleDB) GetRevokedCertificates() (*[]RevokedCertificateInfo, error) {
	return nil, ErrNotImplemented
}

// GetCRL returns a "NotImplemented" error.
func (s *SimpleDB) GetCRL() (*CertificateRevocationListInfo, error) {
	return nil, ErrNotImplemented
}

// StoreCRL returns a "NotImplemented" error.
func (s *SimpleDB) StoreCRL(*CertificateRevocationListInfo) error {
	return ErrNotImplemented
}

// RevokeSSH returns a "NotImplemented" error.
func (s *SimpleDB) RevokeSSH(*RevokedCertificateInfo) error {
	return ErrNotImplemented
}

// GetCertificate returns a "NotImplemented" error.
func (s *SimpleDB) GetCertificate(string) (*x509.Certificate, error) {
	return nil, ErrNotImplemented
}

// StoreCertificate returns a "NotImplemented" error.
func (s *SimpleDB) StoreCertificate(*x509.Certificate) error {
	return ErrNotImplemented
}

type usedToken struct {
	UsedAt    int64  `json:"ua,omitempty"`
	ExpiresAt int64  `json:"ea,omitempty"`
	Token     string `json:"tok,omitempty"`
}

// expired reports whether the record has outlived the validity of the token
// it belongs to. Records without an expiry never expire.
func (t *usedToken) expired(now time.Time) bool {
	return t.ExpiresAt > 0 && !now.Before(time.Unix(t.ExpiresAt, 0))
}

// usedTokenExpiry returns the time at which a record of the given token no
// longer needs to be retained. It is derived from the expiration claim of
// the token; if the token validity cannot be determined, a conservative
// default retention is used.
func usedTokenExpiry(tok string, now time.Time) time.Time {
	if t, err := jose.ParseSigned(tok); err == nil {
		var claims jose.Claims
		if err := t.UnsafeClaimsWithoutVerification(&claims); err == nil && claims.Expiry != nil {
			return claims.Expiry.Time()
		}
	}
	return now.Add(defaultUsedTokenRetention)
}

// UseToken returns true if we were able to successfully store the token for
// the first time, false otherwise. The record is persisted so that the
// protection against token reuse survives restarts, and it expires with the
// validity of the token.
func (s *SimpleDB) UseToken(id, tok string) (bool, error) {
	now := time.Now()
	ut := &usedToken{
		UsedAt:    now.Unix(),
		ExpiresAt: usedTokenExpiry(tok, now).Unix(),
		Token:     tok,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.usedTokens.Load(id); ok {
		if existing := v.(*usedToken); !existing.expired(now) {
			// Token already exists in DB.
			return false, nil
		}
		// The previous record expired with the validity of the token, so
		// the token itself can no longer be valid and the record can be
		// replaced.
		s.usedTokens.Delete(id)
	}
	s.usedTokens.Store(id, ut)
	if err := s.persistUsedTokens(); err != nil {
		// Fail closed: without a durable record the one-time use promise
		// cannot be kept across restarts.
		s.usedTokens.Delete(id)
		return false, errors.Wrap(err, "error storing used token")
	}
	// Successfully stored token.
	return true, nil
}

// loadUsedTokens reads the persisted used token records, skipping the ones
// that have expired. A missing file is not an error.
func (s *SimpleDB) loadUsedTokens() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return errors.Wrap(err, "error creating used token directory")
	}
	b, err := os.ReadFile(s.path)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return errors.Wrap(err, "error reading used tokens file")
	}
	var tokens map[string]usedToken
	if err := json.Unmarshal(b, &tokens); err != nil {
		return errors.Wrap(err, "error parsing used tokens file")
	}
	now := time.Now()
	for id, tok := range tokens {
		t := tok
		if t.expired(now) {
			continue
		}
		s.usedTokens.Store(id, &t)
	}
	return nil
}

// persistUsedTokens writes the used token records to disk, sweeping expired
// records to bound the size of the map and the file. The file is replaced
// atomically so a crash cannot leave a partially written file behind. It is
// a noop if no data source is configured. Callers must hold s.mu.
func (s *SimpleDB) persistUsedTokens() error {
	if s.path == "" {
		return nil
	}
	now := time.Now()
	tokens := make(map[string]usedToken)
	s.usedTokens.Range(func(k, v any) bool {
		id, t := k.(string), v.(*usedToken)
		if t.expired(now) {
			s.usedTokens.Delete(id)
			return true
		}
		tokens[id] = *t
		return true
	})
	b, err := json.Marshal(tokens)
	if err != nil {
		return errors.Wrap(err, "error marshaling used tokens")
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return errors.Wrap(err, "error writing used tokens file")
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return errors.Wrap(err, "error replacing used tokens file")
	}
	return nil
}

// IsSSHHost returns a "NotImplemented" error.
func (s *SimpleDB) IsSSHHost(string) (bool, error) {
	return false, ErrNotImplemented
}

// StoreSSHCertificate returns a "NotImplemented" error.
func (s *SimpleDB) StoreSSHCertificate(*ssh.Certificate) error {
	return ErrNotImplemented
}

// GetSSHHostPrincipals returns a "NotImplemented" error.
func (s *SimpleDB) GetSSHHostPrincipals() ([]string, error) {
	return nil, ErrNotImplemented
}

// Shutdown returns nil
func (s *SimpleDB) Shutdown() error {
	return nil
}

// nosql.DB interface implementation //

// Open opens the database available with the given options.
func (s *SimpleDB) Open(string, ...database.Option) error {
	return ErrNotImplemented
}

// Close closes the current database.
func (s *SimpleDB) Close() error {
	return ErrNotImplemented
}

// Get returns the value stored in the given table/bucket and key.
func (s *SimpleDB) Get([]byte, []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// Set sets the given value in the given table/bucket and key.
func (s *SimpleDB) Set([]byte, []byte, []byte) error {
	return ErrNotImplemented
}

// CmpAndSwap swaps the value at the given bucket and key if the current
// value is equivalent to the oldValue input. Returns 'true' if the
// swap was successful and 'false' otherwise.
func (s *SimpleDB) CmpAndSwap([]byte, []byte, []byte, []byte) ([]byte, bool, error) {
	return nil, false, ErrNotImplemented
}

// Del deletes the data in the given table/bucket and key.
func (s *SimpleDB) Del([]byte, []byte) error {
	return ErrNotImplemented
}

// List returns a list of all the entries in a given table/bucket.
func (s *SimpleDB) List([]byte) ([]*database.Entry, error) {
	return nil, ErrNotImplemented
}

// Update performs a transaction with multiple read-write commands.
func (s *SimpleDB) Update(*database.Tx) error {
	return ErrNotImplemented
}

// CreateTable creates a table or a bucket in the database.
func (s *SimpleDB) CreateTable([]byte) error {
	return ErrNotImplemented
}

// DeleteTable deletes a table or a bucket in the database.
func (s *SimpleDB) DeleteTable([]byte) error {
	return ErrNotImplemented
}
