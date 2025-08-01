package acme

import (
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/coredns/caddy"
)

const (
	ENABLED                          = "enabled"
	DOMAIN                           = "domain"
	EMAIL                            = "email"
	AUTHORITATIVE_NAMESERVER         = "authoritative_nameserver"
	AUTHORITATIVE_NAMESERVER_IP_ADDR = "ip"
	AUTHORITATIVE_NAMESERVER_HOST    = "host"
	ELECTION_PROPOSAL                = "election_proposal"
)

type nameserver struct {
	host string
	ip   string
}

type config struct {
	enabled                 bool
	zone                    string
	authoritativeNameserver nameserver
	email                   string
	electionProposal        string
}

func defaultConfig() config {
	return config{
		enabled: true,
		zone:    "",
		authoritativeNameserver: nameserver{
			host: "",
			ip:   "",
		},
		email:            "",
		electionProposal: "",
	}
}

func parseConfig(c *caddy.Controller) (config, error) {
	cfg := defaultConfig()

	for c.Next() {
		for c.NextBlock() {
			term := strings.ToLower(c.Val())
			switch term {
			case ENABLED:
				args := c.RemainingArgs()
				if len(args) != 1 {
					return config{}, c.Errf("expected one argument for %s, got: %#v", ENABLED, args)
				}
				switch strings.ToLower(args[0]) {
				case "true":
					cfg.enabled = true
				case "false":
					cfg.enabled = false
				default:
					return config{}, c.Errf("expected 'true' or 'false' for %s, got: %s", ENABLED, args[0])
				}
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
			case ELECTION_PROPOSAL:
				args := c.RemainingArgs()
				if len(args) != 1 {
					return config{}, c.Errf("expected one argument for %s, got: %#v", ELECTION_PROPOSAL, args)
				}
				cfg.electionProposal = args[0]
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
	if cfg.electionProposal == "" {
		return config{}, c.Errf("Election proposal not provided")
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
