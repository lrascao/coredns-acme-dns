package acme

import (
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/caddy"
)

const (
	DOMAIN                           = "domain"
	EMAIL                            = "email"
	AUTHORITATIVE_NAMESERVER         = "authoritative_nameserver"
	AUTHORITATIVE_NAMESERVER_IP_ADDR = "ip"
	AUTHORITATIVE_NAMESERVER_HOST    = "host"
)

type nameserver struct {
	host string
	ip   string
}

type config struct {
	zone                    string
	authoritativeNameserver nameserver
	email                   string
}

func parseConfig(c *caddy.Controller) (config, error) {
	var cfg config

	for c.Next() {
		for c.NextBlock() {
			term := strings.ToLower(c.Val())
			switch term {
			case DOMAIN:
				args := c.RemainingArgs()
				if len(args) > 1 {
					return config{}, c.Errf("unexpected number of arguments: %#v", args)
				}
				cfg.zone = args[0]
			case EMAIL:
				args := c.RemainingArgs()
				if len(args) != 1 {
					return config{}, c.Errf("expected one argument for %s, got: %#v", EMAIL, args)
				}
				cfg.email = args[0]
			case AUTHORITATIVE_NAMESERVER:
				for c.NextBlock() {
					term := strings.ToLower(c.Val())
					switch term {
					case AUTHORITATIVE_NAMESERVER_HOST:
						args := c.RemainingArgs()
						if len(args) != 1 {
							return config{}, c.Errf("expected one argument for %s, got: %#v", AUTHORITATIVE_NAMESERVER_HOST, args)
						}
						cfg.authoritativeNameserver.host = args[0]
					case AUTHORITATIVE_NAMESERVER_IP_ADDR:
						args := c.RemainingArgs()
						if len(args) != 1 {
							return config{}, c.Errf("expected one argument for %s, got: %#v", AUTHORITATIVE_NAMESERVER_IP_ADDR, args)
						}
						cfg.authoritativeNameserver.ip = args[0]
					}
				}
			default:
				return config{}, c.Errf("unexpected term: %s", term)
			}
		}
	}

	if cfg.zone == "" {
		return config{}, c.Errf("Domain not provided")
	}
	if cfg.email == "" {
		return config{}, c.Errf("Email not provided")
	}
	if len(cfg.authoritativeNameserver.host) == 0 && len(cfg.authoritativeNameserver.ip) == 0 {
		return config{}, c.Errf("Authoritative nameserver details not provided")
	}

	return cfg, nil
}

func issuerFromConfig(provider certmagic.DNSProvider, cfg config) certmagic.ACMEIssuer {
	return certmagic.ACMEIssuer{
		Email:                   cfg.email,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		// CA:                      certmagic.LetsEncryptProductionCA,
		CA: certmagic.LetsEncryptStagingCA,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: provider,
				Resolvers:   []string{cfg.authoritativeNameserver.host},
			},
		},
	}
}
