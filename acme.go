package acme

import (
	"context"
	"fmt"

	"github.com/caddyserver/certmagic"
)

type ACME struct {
	Manager *certmagic.ACMEIssuer
	Config  *certmagic.Config
	Zone    string
}

func NewACME(acmeManagerTemplate certmagic.ACMEIssuer, cfg *certmagic.Config, zone string) ACME {
	cache := certmagic.NewCache(
		certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
				return cfg, nil
			},
		})
	config := certmagic.New(cache, *cfg)
	acmeManager := certmagic.NewACMEIssuer(config, acmeManagerTemplate)
	config.Issuers = []certmagic.Issuer{acmeManager}
	return ACME{
		Config:  config,
		Manager: acmeManager,
		Zone:    zone,
	}
}

func (a ACME) IssueCert(ctx context.Context, zones []string) error {
	if err := a.Config.ManageSync(ctx, zones); err != nil {
		return fmt.Errorf("failed to manage sync for zones %v: %w", zones, err)
	}

	return nil
}

func (a ACME) GetCert(ctx context.Context, zone string) error {
	if err := a.Config.ObtainCertSync(ctx, zone); err != nil {
		return fmt.Errorf("failed to obtain cert for zone %s: %w", zone, err)
	}

	return nil
}

func (a ACME) RevokeCert(zone string) error {
	if err := a.Config.RevokeCert(context.Background(), zone, 0, false); err != nil {
		return fmt.Errorf("failed to revoke cert for zone %s: %w", zone, err)
	}

	return nil
}
