package acme

import (
	"context"
	"fmt"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	coredns_etcd "github.com/lrascao/coredns-etcd"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("acme")

const (
	pluginName   = "acme"
	electionName = "acme-dns01"
)

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

	c.OnFirstStartup(func() error {
		var election coredns_etcd.Election
		// find the plugin that satisfies the election interface
		for _, p := range dnsserver.GetConfig(c).Handlers() {
			if e, ok := p.(coredns_etcd.Election); ok {
				election = e
				break
			}
		}
		if election == nil {
			return fmt.Errorf("no election plugin found, ACME requires an election plugin to function")
		}

		go func() {
			log.Infof("Campaigning on election %s for ACME DNS-01 challenge with proposal %s",
				electionName, cfg.electionProposal)

			err := election.Campaign(ctx,
				coredns_etcd.WithElection(electionName),
				coredns_etcd.WithProposal(cfg.electionProposal),
				coredns_etcd.WithCallback(
					func(ctx context.Context) error {
						log.Infof("Won the election for ACME DNS-01 challenge with proposal %s",
							cfg.electionProposal)
						if !cfg.enabled {
							log.Info("ACME plugin is disabled, skipping certificate issuance")
							return nil
						}

						// find the plugin that satisfies certmagic's DNSProvider interface
						var provider certmagic.DNSProvider
						for _, h := range dnsserver.GetConfig(c).Handlers() {
							if p, ok := h.(certmagic.DNSProvider); ok {
								provider = p
								break
							}
						}
						if provider == nil {
							return fmt.Errorf("no DNSProvider found, ACME requires a DNSProvider to function")
						}

						acmeTemplate := issuerFromConfig(provider, cfg)
						certmagicCfg := certmagic.NewDefault()
						acme := NewACME(acmeTemplate, certmagicCfg, cfg.zone)
						if err := acme.IssueCert(ctx, []string{cfg.zone}); err != nil {
							log.Error(err)
							return fmt.Errorf("failed to issue certificate for zone %s: %w", cfg.zone, err)
						}

						return nil
					}))
			if err != nil {
				log.Errorf("Error starting ACME election: %v", err)
			}
		}()

		return nil
	})
	return nil
}
