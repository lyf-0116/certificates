package authority

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/administrator"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/linkedca"
)

// adminTestAuthority builds an authority with an admin registered for the
// step-cli provisioner and a storage backend that records every token
// reservation it receives.
func adminTestAuthority(t *testing.T, authDB db.AuthDB) (*Authority, crypto.Signer) {
	t.Helper()

	a := testAuthority(t)

	prov, err := a.LoadProvisionerByName("step-cli")
	assert.FatalError(t, err)

	a.admins = administrator.NewCollection(a.provisioners)
	assert.FatalError(t, a.admins.Store(&linkedca.Admin{
		Id:            "adminID",
		Subject:       "admin.example.com",
		ProvisionerId: prov.GetID(),
		Type:          linkedca.Admin_SUPER_ADMIN,
	}, prov))

	if authDB != nil {
		a.db = authDB
	}

	_, signer, err := ed25519.GenerateKey(rand.Reader)
	assert.FatalError(t, err)

	return a, signer
}

// generateAdminX5cToken signs an x5c admin JWT with the given claims. The leaf
// certificate embedded in the x5c header is issued by the test authority and
// carries the step-cli provisioner extension so it can be resolved back to the
// provisioner. The leaf certificate is issued for the given DNS names.
func generateAdminX5cToken(t *testing.T, a *Authority, signer crypto.Signer, claims jose.Claims, dnsNames ...string) string {
	t.Helper()

	if len(dnsNames) == 0 {
		dnsNames = []string{"admin.example.com"}
	}
	commonName := dnsNames[0]

	csr, err := x509util.CreateCertificateRequest(commonName, dnsNames, signer)
	assert.FatalError(t, err)

	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
	chain, err := a.SignWithContext(ctx, csr, provisioner.SignOptions{}, provisioner.CertificateEnforcerFunc(func(cert *x509.Certificate) error {
		cert.NotBefore = time.Now().Add(-time.Minute)
		cert.NotAfter = time.Now().Add(time.Hour)
		b, err := asn1.Marshal(stepProvisionerASN1{
			Type: int(provisioner.TypeJWK),
			Name: []byte("step-cli"),
		})
		if err != nil {
			return err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
			Id:    provisioner.StepOIDProvisioner,
			Value: b,
		})
		return nil
	}))
	assert.FatalError(t, err)

	var x5c []string
	for _, c := range chain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}

	so := new(jose.SignerOptions)
	so.WithType("JWT")
	so.WithHeader("x5c", x5c)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: signer}, so)
	assert.FatalError(t, err)

	raw, err := jose.Signed(sig).Claims(claims).Serialize()
	assert.FatalError(t, err)
	return raw
}

func adminClaims(now time.Time) jose.Claims {
	return jose.Claims{
		Audience:  []string{"https://example.com/admin/admins"},
		Subject:   "admin.example.com",
		Issuer:    "step-admin-client/1.0",
		NotBefore: jose.NewNumericDate(now.Add(-time.Minute)),
		Expiry:    jose.NewNumericDate(now.Add(5 * time.Minute)),
		IssuedAt:  jose.NewNumericDate(now),
		ID:        "admin-token-id",
	}
}

func adminRequest() *http.Request {
	return httptest.NewRequest("GET", "https://example.com/admin/admins", http.NoBody)
}

func TestAuthority_AuthorizeAdminToken(t *testing.T) {
	now := time.Now().UTC()

	t.Run("ok consumes the token after validation", func(t *testing.T) {
		var reserved []string
		authDB := &db.MockAuthDB{
			MReserveToken: func(id, tok string) (bool, error) {
				reserved = append(reserved, id)
				return true, nil
			},
		}
		a, signer := adminTestAuthority(t, authDB)
		token := generateAdminX5cToken(t, a, signer, adminClaims(now))

		adm, err := a.AuthorizeAdminToken(adminRequest(), token)
		assert.FatalError(t, err)
		assert.Equals(t, "adminID", adm.Id)
		assert.Equals(t, 1, len(reserved))
	})

	t.Run("fail/expired token is rejected without reserving", func(t *testing.T) {
		var reserved int
		authDB := &db.MockAuthDB{
			MReserveToken: func(id, tok string) (bool, error) {
				reserved++
				return true, nil
			},
		}
		a, signer := adminTestAuthority(t, authDB)

		claims := adminClaims(now)
		claims.Expiry = jose.NewNumericDate(now.Add(-time.Hour))
		claims.NotBefore = jose.NewNumericDate(now.Add(-2 * time.Hour))
		token := generateAdminX5cToken(t, a, signer, claims)

		_, err := a.AuthorizeAdminToken(adminRequest(), token)
		assert.NotNil(t, err)
		assert.Equals(t, 0, reserved)

		// Replaying the same rejected token must still not reserve anything.
		_, err = a.AuthorizeAdminToken(adminRequest(), token)
		assert.NotNil(t, err)
		assert.Equals(t, 0, reserved)
	})

	t.Run("fail/invalid audience is rejected without reserving", func(t *testing.T) {
		var reserved int
		authDB := &db.MockAuthDB{
			MReserveToken: func(id, tok string) (bool, error) {
				reserved++
				return true, nil
			},
		}
		a, signer := adminTestAuthority(t, authDB)

		claims := adminClaims(now)
		claims.Audience = []string{"https://example.com/somewhere-else"}
		token := generateAdminX5cToken(t, a, signer, claims)

		_, err := a.AuthorizeAdminToken(adminRequest(), token)
		assert.NotNil(t, err)
		assert.Equals(t, 0, reserved)
	})

	t.Run("fail/unknown admin is rejected without reserving", func(t *testing.T) {
		var reserved int
		authDB := &db.MockAuthDB{
			MReserveToken: func(id, tok string) (bool, error) {
				reserved++
				return true, nil
			},
		}
		a, signer := adminTestAuthority(t, authDB)

		claims := adminClaims(now)
		claims.Subject = "stranger.example.com"
		token := generateAdminX5cToken(t, a, signer, claims, "stranger.example.com")

		_, err := a.AuthorizeAdminToken(adminRequest(), token)
		assert.NotNil(t, err)
		assert.Equals(t, 0, reserved)
	})

	t.Run("fail/replayed token is rejected by the reservation", func(t *testing.T) {
		authDB := &db.MockAuthDB{
			MReserveToken: func(id, tok string) (bool, error) {
				return false, nil
			},
		}
		a, signer := adminTestAuthority(t, authDB)
		token := generateAdminX5cToken(t, a, signer, adminClaims(now))

		_, err := a.AuthorizeAdminToken(adminRequest(), token)
		assert.NotNil(t, err)
		assert.HasPrefix(t, err.Error(), "adminHandler.authorizeToken; error with reuse token")
	})

	t.Run("fallback/backend without reservation keeps legacy ordering", func(t *testing.T) {
		var used int
		authDB := &legacyOnlyAuthDB{
			useToken: func(id, tok string) (bool, error) {
				used++
				return true, nil
			},
		}
		a, signer := adminTestAuthority(t, authDB)
		token := generateAdminX5cToken(t, a, signer, adminClaims(now))

		adm, err := a.AuthorizeAdminToken(adminRequest(), token)
		assert.FatalError(t, err)
		assert.Equals(t, "adminID", adm.Id)
		assert.Equals(t, 1, used)
	})

	t.Run("fallback/expired token still consumes on legacy backend", func(t *testing.T) {
		var used int
		authDB := &legacyOnlyAuthDB{
			useToken: func(id, tok string) (bool, error) {
				used++
				return true, nil
			},
		}
		a, signer := adminTestAuthority(t, authDB)

		claims := adminClaims(now)
		claims.Expiry = jose.NewNumericDate(now.Add(-time.Hour))
		claims.NotBefore = jose.NewNumericDate(now.Add(-2 * time.Hour))
		token := generateAdminX5cToken(t, a, signer, claims)

		_, err := a.AuthorizeAdminToken(adminRequest(), token)
		assert.NotNil(t, err)
		// The legacy backend cannot separate validation from consumption, so the
		// rejected token still occupies a record.
		assert.Equals(t, 1, used)
	})

	t.Run("ok/concurrent requests reserve the token only once", func(t *testing.T) {
		var (
			mu       sync.Mutex
			reserved []string
		)
		authDB := &db.MockAuthDB{
			MReserveToken: func(id, tok string) (bool, error) {
				mu.Lock()
				defer mu.Unlock()
				for _, existing := range reserved {
					if existing == id {
						return false, nil
					}
				}
				reserved = append(reserved, id)
				return true, nil
			},
		}
		a, signer := adminTestAuthority(t, authDB)
		token := generateAdminX5cToken(t, a, signer, adminClaims(now))

		const requests = 20
		var (
			wg      sync.WaitGroup
			allowed int64
			denied  int64
		)
		wg.Add(requests)
		for i := 0; i < requests; i++ {
			go func() {
				defer wg.Done()
				if _, err := a.AuthorizeAdminToken(adminRequest(), token); err == nil {
					atomic.AddInt64(&allowed, 1)
				} else {
					atomic.AddInt64(&denied, 1)
				}
			}()
		}
		wg.Wait()

		assert.Equals(t, int64(1), atomic.LoadInt64(&allowed))
		assert.Equals(t, int64(requests-1), atomic.LoadInt64(&denied))
		assert.Equals(t, 1, len(reserved))
	})
}

// legacyOnlyAuthDB implements db.AuthDB without implementing db.TokenReserver,
// simulating an external storage backend that has not been upgraded with the
// atomic reservation semantics.
type legacyOnlyAuthDB struct {
	useToken func(id, tok string) (bool, error)
}

func (m *legacyOnlyAuthDB) IsRevoked(string) (bool, error)             { return false, nil }
func (m *legacyOnlyAuthDB) IsSSHRevoked(string) (bool, error)          { return false, nil }
func (m *legacyOnlyAuthDB) Revoke(*db.RevokedCertificateInfo) error    { return nil }
func (m *legacyOnlyAuthDB) RevokeSSH(*db.RevokedCertificateInfo) error { return nil }
func (m *legacyOnlyAuthDB) GetCertificate(string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *legacyOnlyAuthDB) UseToken(id, tok string) (bool, error) {
	return m.useToken(id, tok)
}
func (m *legacyOnlyAuthDB) IsSSHHost(string) (bool, error) { return false, nil }
func (m *legacyOnlyAuthDB) GetSSHHostPrincipals() ([]string, error) {
	return nil, nil
}
func (m *legacyOnlyAuthDB) Shutdown() error { return nil }
