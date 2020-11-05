package alidns

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	alidns "github.com/ccdai/libdns_alidns"
)

// Provider wraps the provider implementation as a Caddy module.
type Provider struct{ *alidns.Provider }

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.alidns",
		New: func() caddy.Module { return &Provider{new(alidns.Provider)} },
	}
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
// alidns {
//     accesskey_id <accesskey_id>
//     accesskey_secret <accesskey_secret>
//     region_id <region_id>
// }
//
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	repl := caddy.NewReplacer()
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "accesskey_id":
				if d.NextArg() {
					p.Provider.AccessKeyID = repl.ReplaceAll(d.Val(), "")
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "accesskey_secret":
				if d.NextArg() {
					p.Provider.AccessKeySecret = repl.ReplaceAll(d.Val(), "")
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "region_id":
				if d.NextArg() {
					p.Provider.RegionID = repl.ReplaceAll(d.Val(), "")
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.Provider.AccessKeyID == "" {
		return d.Err("missing access key id")
	}
	if p.Provider.AccessKeySecret == "" {
		return d.Err("missing access key secret")
	}
	return nil
}

// Interface guard
var _ caddyfile.Unmarshaler = (*Provider)(nil)
