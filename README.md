# acme-dns
![CI Workflow](https://github.com/lrascao/coredns-acme-dns/actions/workflows/go.yml/badge.svg)
[![codecov](https://codecov.io/gh/lrascao/coredns-acme-dns/branch/main/graph/badge.svg)](https://codecov.io/gh/lrascao/coredns-acme-dns)

## Getting Started
### Configuration
#### Basic
~~~txt
acme {
  domain <DOMAIN>
  email <EMAIL>
  authoritative_nameserver {
    host <HOST>
    ip <IP>
  }
}
~~~

* `DOMAIN` is the domain name the plugin should be authoritative for.
* `EMAIL` is the email address to be used for ACME registration.
* `HOST` is the hostname of the authoritative nameserver for the domain.
* `IP` is the IP address of the authoritative nameserver for the domain.

### Examples
#### Basic
~~~txt
acme {
  domain contoso.com
  email your-email@provider.com
  authoritative_nameserver {
    host ns1.contoso.com
    ip 1.1.1.1
  }
}
~~~
This will perform ACME for `contoso.com`.

### Installation
This is a CoreDNS plugin so you need to set up CoreDNS first.
#### Basic
If you have Golang installed, you can execute the script below to build the binary.
```bash
# Clone CoreDNS
git clone https://github.com/coredns/coredns
cd coredns

# Add acmedns:github.com/lrascao/coredns-acme-dns into the plugin configuration
echo "acmedns:github.com/lrascao/coredns-acme-dns" >> plugin.cfg

# Get the modules
go get github.com/lrascao/coredns-acme-dns

# Generate Files
go generate

# Tidy the modules
go mod tidy

# Compile
go build
```
### Disclaimer
Make sure you have the following conditions: 
* You own the domain
* Your CoreDNS server is the authoritative nameserver for the domain

