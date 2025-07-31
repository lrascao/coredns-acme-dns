package acme

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestConfig(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		shouldErr bool
		cfg       config
		zoneName  string
	}{
		{
			"Correct Config with only DNS challenge",
			`acme {
				domain test.domain
				email test@test.com
				authoritative_nameserver {
					host ns1.test.domain
					ip 1.1.1.1
				}
			}`,
			false,
			config{
				zone: "test.domain",
				authoritativeNameserver: nameserver{
					host: "ns1.test.domain",
					ip:   "1.1.1.1",
				},
				email: "test@test.com",
			},
			"test.domain",
		},
		{
			"Missing domain",
			`acme {
				email hello
			}`,
			true,
			config{},
			"",
		},
		{
			"Missing email",
			`acme {
				domain test.domain
			}`,
			true,
			config{},
			"",
		},
		{
			"Missing authoritative nameserver",
			`acme {
				email hello
				domain test.domain
			}`,
			true,
			config{},
			"",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := caddy.NewTestController("acme", test.input)
			cfg, err := parseConfig(c)
			if (err != nil) != test.shouldErr {
				t.Errorf("Error: setup() error = %v, shouldErr %v", err, test.shouldErr)
			} else {
				if !test.shouldErr {
					if !compareConfig(test.cfg, cfg) {
						t.Errorf("Error: config %+v is not as it should be %+v", cfg, test.cfg)
					}
				}
			}
		})
	}
}

func compareConfig(a, b config) bool {
	return a.zone == b.zone &&
		a.email == b.email &&
		a.authoritativeNameserver.host == b.authoritativeNameserver.host &&
		a.authoritativeNameserver.ip == b.authoritativeNameserver.ip
}
