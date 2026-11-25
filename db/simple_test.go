package db

import (
	"sync"
	"sync/atomic"
	"testing"

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

	// ReserveToken shares the same records as UseToken: "foo" was already
	// consumed above, so the reservation must fail without writing anything.
	ok, err = db.ReserveToken("foo", "cat")
	assert.False(t, ok)
	assert.Nil(t, err)

	// A fresh id is reserved atomically on the first attempt and rejected on
	// the second one.
	ok, err = db.ReserveToken("baz", "qux")
	assert.True(t, ok)
	assert.Nil(t, err)
	ok, err = db.ReserveToken("baz", "qux")
	assert.False(t, ok)
	assert.Nil(t, err)

	// A reservation also blocks the legacy UseToken path.
	ok, err = db.UseToken("baz", "qux")
	assert.False(t, ok)
	assert.Nil(t, err)

	// Shutdown -- verify noop
	assert.FatalError(t, db.Shutdown())
	ok, err = db.UseToken("foo", "cat")
	assert.False(t, ok)
	assert.Nil(t, err)
}

func TestSimpleDB_ReserveTokenConcurrent(t *testing.T) {
	db, err := newSimpleDB(nil)
	assert.FatalError(t, err)

	const goroutines = 50
	var (
		wg      sync.WaitGroup
		success int64
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ok, err := db.ReserveToken("same-id", "token")
			assert.Nil(t, err)
			if ok {
				atomic.AddInt64(&success, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equals(t, int64(1), atomic.LoadInt64(&success))
}
