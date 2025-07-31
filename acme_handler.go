package acme

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type AcmeHandler struct {
	Next     plugin.Handler
	provider *Provider
	*AcmeConfig
}

type AcmeConfig struct {
	Zone                    string
	Ipv4Addr                net.IP
	Ipv6Addr                net.IP
	AuthoritativeNameserver string
}

const (
	dnsChallengeString   = "_acme-challenge."
	certificateAuthority = "letsencrypt.org"
)

func (h AcmeHandler) Name() string {
	log.Debugf("acmeHandler.Name: %s", pluginName)
	return pluginName
}

func (h AcmeHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	a := new(dns.Msg)
	a.SetReply(state.Req)
	a.Answer = []dns.RR{}
	class := state.QClass()
	for _, question := range r.Question {
		zone := plugin.Zones([]string{getQualifiedZone(h.Zone)}).Matches(question.Name)
		if zone == "" {
			log.Errorf("acmeHandler.ServeDNS: no matching zone for question %s (zone: %s)",
				question.Name, h.Zone)
			return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
		}

		log.Infof("dns: question: %s, zone: %s, class: %d",
			question.Name, zone, class)
		if checkDNSChallenge(question.Name) {
			switch question.Qtype {
			case dns.TypeSOA:
				h.handleSOA(ctx, zone, class, a)
			case dns.TypeTXT:
				if err := h.solveDNSChallenge(ctx, zone, class, a); err != nil {
					log.Errorf("error solving DNS challenge for zone %s err: %v", zone, err)
					return 0, fmt.Errorf("error solving DNS challenge for zone %s: %w", zone, err)
				}
			case dns.TypeNS:
				rr := new(dns.NS)
				rr.Ns = h.AuthoritativeNameserver
				rr.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: class}
				a.Answer = append(a.Answer, rr)
			case dns.TypeA:
				h.handleA(ctx, zone, class, a)
			case dns.TypeAAAA:
				h.handleAAAA(ctx, zone, class, a)
			}
		}
	}

	if len(a.Answer) != 0 {
		if err := w.WriteMsg(a); err != nil {
			log.Errorf("error writing DNS response: %v", err)
			return 0, fmt.Errorf("error writing DNS response: %w", err)
		}
	}

	return dns.RcodeSuccess, nil
}

func checkDNSChallenge(zone string) bool {
	return strings.HasPrefix(zone, dnsChallengeString)
}

func (h *AcmeHandler) solveDNSChallenge(ctx context.Context, zone string, class uint16, a *dns.Msg) error {
	a.Authoritative = true
	records, err := h.provider.GetRecords(ctx, zone)
	if err != nil {
		return fmt.Errorf("error getting records for zone %s: %w", zone, err)
	}

	var rrs []dns.RR
	for _, record := range records {
		rrs = append(rrs,
			&dns.TXT{
				Txt: []string{record.RR().Data},
				Hdr: dns.RR_Header{
					Name:   zone,
					Rrtype: dns.TypeTXT,
					Class:  class,
					Ttl:    uint32(record.RR().TTL),
				},
			})
	}
	a.Answer = append(a.Answer, rrs...)

	return nil
}

func (h *AcmeHandler) handleSOA(ctx context.Context, name string, class uint16, a *dns.Msg) {
	rr := new(dns.SOA)
	rr.Ns = h.AuthoritativeNameserver
	rr.Mbox = getQualifiedZone(certificateAuthority)
	rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: class}
	rr.Serial = uint32(1)
	rr.Expire = uint32(60)
	rr.Minttl = uint32(60)
	a.Answer = append(a.Answer, rr)
}

func (h *AcmeHandler) handleA(ctx context.Context, name string, class uint16, a *dns.Msg) {
	rr := new(dns.A)
	rr.A = h.Ipv4Addr
	rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: class}
	a.Answer = append(a.Answer, rr)
}

func (h *AcmeHandler) handleAAAA(ctx context.Context, name string, class uint16, a *dns.Msg) {
	rr := new(dns.AAAA)
	rr.AAAA = h.Ipv6Addr
	rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: class}
	a.Answer = append(a.Answer, rr)
}

func getQualifiedZone(zone string) string {
	if !strings.HasSuffix(zone, ".") {
		return zone + "."
	}
	return zone
}
