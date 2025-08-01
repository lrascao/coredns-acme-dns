package acme

import (
	"context"
	"fmt"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
)

const pluginName = "acme"

func init() {
	plugin.Register(pluginName, setup)
}

func setup(c *caddy.Controller) error {
	ctx := context.Background()

	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	log.Infof("ACME configuration: %+v", cfg)

	provider := NewProvider()

	acmeTemplate := issuerFromConfig(provider, cfg)

	config := dnsserver.GetConfig(c)
	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		return AcmeHandler{
			Next:     next,
			provider: provider,
			AcmeConfig: &AcmeConfig{
				Zone: cfg.zone,
			},
		}
	})

	c.OnFirstStartup(func() error {
		if !cfg.enabled {
			log.Info("ACME plugin is disabled, skipping certificate issuance")
			return nil
		}

		go func() error {
			certmagicCfg := certmagic.NewDefault()
			acme := NewACME(acmeTemplate, certmagicCfg, cfg.zone)
			if err := acme.IssueCert(ctx, []string{cfg.zone}); err != nil {
				log.Error(err)
				return fmt.Errorf("failed to issue certificate for zone %s: %w", cfg.zone, err)
			}

			return nil
		}()
		return nil
	})
	return nil
}
