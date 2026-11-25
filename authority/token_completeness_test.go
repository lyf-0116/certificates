package authority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"go.step.sm/crypto/jose"
)

func signRegressionToken(t *testing.T, claims jose.Claims) string {
	t.Helper()
	jwk, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	assert.FatalError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID))
	assert.FatalError(t, err)
	token, err := jose.Signed(signer).Claims(claims).Serialize()
	assert.FatalError(t, err)
	return token
}

func TestAuthorizeTokenMissingIssuedAtRejectedBeforeUse(t *testing.T) {
	used := false
	a := testAuthority(t, WithDatabase(&db.MockAuthDB{
		MUseToken: func(string, string) (bool, error) {
			used = true
			return true, nil
		},
	}))

	now := time.Now().UTC()
	token := signRegressionToken(t, jose.Claims{
		Subject:   "test.smallstep.com",
		Issuer:    "step-cli",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
		Audience:  []string{"https://example.com/revoke"},
		ID:        "token-id",
	})

	_, err := a.authorizeToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected missing iat token to be rejected")
	}
	var sc render.StatusCodedError
	if !errors.As(err, &sc) || sc.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthorized error, got %v", err)
	}
	if used {
		t.Fatal("UseToken must not be called when required claims are missing")
	}
}

func TestUseTokenHashesTokenAfterUnexpectedGetIDError(t *testing.T) {
	rawToken := "raw-token"
	sum := sha256.Sum256([]byte(rawToken))
	expectedKey := hex.EncodeToString(sum[:])
	var gotKey string
	a := testAuthority(t, WithDatabase(&db.MockAuthDB{
		MUseToken: func(key, token string) (bool, error) {
			gotKey = key
			assert.Equals(t, rawToken, token)
			return true, nil
		},
	}))
	prov := &provisioner.MockProvisioner{
		MgetTokenID: func(string) (string, error) {
			return "", errors.New("identifier unavailable")
		},
	}

	if err := a.UseToken(context.Background(), rawToken, prov); err != nil {
		t.Fatalf("UseToken() error = %v", err)
	}
	assert.Equals(t, expectedKey, gotKey)
}

func TestAuthorizeTokenWithoutJTIStillUsesHashFallback(t *testing.T) {
	a := testAuthority(t)
	now := time.Now().UTC()
	token := signRegressionToken(t, jose.Claims{
		Subject:   "test.smallstep.com",
		Issuer:    "step-cli",
		IssuedAt:  jose.NewNumericDate(now),
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
		Audience:  []string{"https://example.com/revoke"},
	})

	if _, err := a.authorizeToken(context.Background(), token); err != nil {
		t.Fatalf("first authorizeToken() error = %v", err)
	}
	_, err := a.authorizeToken(context.Background(), token)
	if err == nil || err.Error() != "token already used" {
		t.Fatalf("second authorizeToken() error = %v, want token already used", err)
	}
}

func TestAuthorizeTokenAllowsMissingIATWhenCheckDisabled(t *testing.T) {
	a := testAuthority(t)
	a.config.AuthorityConfig.DisableIssuedAtCheck = true

	now := time.Now().UTC()
	token := signRegressionToken(t, jose.Claims{
		Subject:   "test.smallstep.com",
		Issuer:    "step-cli",
		NotBefore: jose.NewNumericDate(now),
		Expiry:    jose.NewNumericDate(now.Add(time.Minute)),
		Audience:  []string{"https://example.com/revoke"},
		ID:        "token-id",
	})

	if _, err := a.authorizeToken(context.Background(), token); err != nil {
		t.Fatalf("authorizeToken() with disabled iat check error = %v", err)
	}
}
