package db

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smallstep/assert"
)

func TestSimpleDB(t *testing.T) {
	db, err := newSimpleDB(nil)
	assert.FatalError(t, err)

	// Revoke
	assert.Equals(t, ErrNotImplemented, db.Revoke(nil))

	// IsRevoked -- verify noop
	isRevoked, err := db.IsRevoked("foo")
	assert.False(t, isRevoked)
	assert.Nil(t, err)

	// StoreCertificate
	assert.Equals(t, ErrNotImplemented, db.StoreCertificate(nil))

	// UseToken
	ok, err := db.UseToken("foo", "bar")
	assert.True(t, ok)
	assert.Nil(t, err)
	ok, err = db.UseToken("foo", "cat")
	assert.False(t, ok)
	assert.Nil(t, err)

	// Shutdown -- verify noop
	assert.FatalError(t, db.Shutdown())
	ok, err = db.UseToken("foo", "cat")
	assert.False(t, ok)
	assert.Nil(t, err)
}

func TestSimpleDBPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "used_tokens.json")

	db1, err := newSimpleDB(&Config{DataSource: path})
	assert.FatalError(t, err)
	ok, err := db1.UseToken("token-id", "token")
	assert.True(t, ok)
	assert.Nil(t, err)

	// Simulate a restart: a new SimpleDB over the same data source must
	// still reject the used token.
	db2, err := newSimpleDB(&Config{DataSource: path})
	assert.FatalError(t, err)
	ok, err = db2.UseToken("token-id", "token")
	assert.False(t, ok)
	assert.Nil(t, err)
	ok, err = db2.UseToken("other-id", "token")
	assert.True(t, ok)
	assert.Nil(t, err)
}

func TestSimpleDBUsedTokenExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "used_tokens.json")
	now := time.Now()

	// Write a file with an expired and a live record.
	tokens := map[string]usedToken{
		"expired-id": {
			UsedAt:    now.Add(-2 * time.Hour).Unix(),
			ExpiresAt: now.Add(-1 * time.Hour).Unix(),
			Token:     "old-token",
		},
		"stale-id": {
			UsedAt:    now.Add(-2 * time.Hour).Unix(),
			ExpiresAt: now.Add(-1 * time.Hour).Unix(),
			Token:     "stale-token",
		},
		"live-id": {
			UsedAt:    now.Add(-time.Minute).Unix(),
			ExpiresAt: now.Add(time.Hour).Unix(),
			Token:     "live-token",
		},
	}
	b, err := json.Marshal(tokens)
	assert.FatalError(t, err)
	assert.FatalError(t, os.WriteFile(path, b, 0o600))

	db, err := newSimpleDB(&Config{DataSource: path})
	assert.FatalError(t, err)

	// Trigger a persist to sweep expired records from the file.
	ok, err := db.UseToken("new-id", "token")
	assert.True(t, ok)
	assert.Nil(t, err)

	// Expired records no longer block a token identifier.
	ok, err = db.UseToken("expired-id", "token")
	assert.True(t, ok)
	assert.Nil(t, err)

	// Live records loaded from disk still block a token identifier.
	ok, err = db.UseToken("live-id", "token")
	assert.False(t, ok)
	assert.Nil(t, err)

	// Expired records are swept from the persisted file.
	b, err = os.ReadFile(path)
	assert.FatalError(t, err)
	var persisted map[string]usedToken
	assert.FatalError(t, json.Unmarshal(b, &persisted))
	if _, ok := persisted["stale-id"]; ok {
		t.Error("expected expired record to be swept from the persisted file")
	}
	if _, ok := persisted["live-id"]; !ok {
		t.Error("expected live record to be retained in the persisted file")
	}
}

func TestUsedTokenExpiry(t *testing.T) {
	now := time.Now()
	exp := now.Add(5 * time.Minute).Truncate(time.Second)

	// A JWT with an expiration claim expires with the token validity.
	claims, err := json.Marshal(map[string]any{"exp": exp.Unix()})
	assert.FatalError(t, err)
	tok := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("signature"))
	assert.Equals(t, exp, usedTokenExpiry(tok, now))

	// A token without a parsable validity gets the default retention.
	got := usedTokenExpiry("not-a-jwt", now)
	assert.Equals(t, now.Add(defaultUsedTokenRetention), got)
	if got.Before(now) {
		t.Errorf("expected fallback retention in the future, got %s", got)
	}
}
