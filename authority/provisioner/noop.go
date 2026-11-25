package provisioner

import (
	"context"
	"crypto/x509"

	"golang.org/x/crypto/ssh"
)

// Noop is a provisioner that accepts anything. It is only used to authorize
// renewals for provisioner names explicitly allowlisted as legacy identifiers;
// it must never be used as an implicit fallback for an unidentifiable issuer.
type Noop struct{}

type noop = Noop

func (p *Noop) GetID() string {
	return "noop"
}

func (p *Noop) GetIDForToken() string {
	return "noop"
}

func (p *Noop) GetTokenID(string) (string, error) {
	return "", nil
}

func (p *Noop) GetName() string {
	return "noop"
}
func (p *Noop) GetType() Type {
	return noopType
}

func (p *Noop) GetEncryptedKey() (kid, key string, ok bool) {
	return "", "", false
}

func (p *Noop) Init(Config) error {
	return nil
}

func (p *Noop) AuthorizeSign(context.Context, string) ([]SignOption, error) {
	return []SignOption{p}, nil
}

func (p *Noop) AuthorizeRenew(context.Context, *x509.Certificate) error {
	return nil
}

func (p *Noop) AuthorizeRevoke(context.Context, string) error {
	return nil
}

func (p *Noop) AuthorizeSSHSign(context.Context, string) ([]SignOption, error) {
	return []SignOption{p}, nil
}

func (p *Noop) AuthorizeSSHRenew(context.Context, string) (*ssh.Certificate, error) {
	//nolint:nilnil // fine for noop
	return nil, nil
}

func (p *Noop) AuthorizeSSHRevoke(context.Context, string) error {
	return nil
}

func (p *Noop) AuthorizeSSHRekey(context.Context, string) (*ssh.Certificate, []SignOption, error) {
	return nil, []SignOption{}, nil
}
