package egress

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestDeclared(t *testing.T) {
	p, err := Parse("https://api.acme.com,https://*.acme.com:8443,http://192.0.2.10", false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cases := []struct {
		raw  string
		want bool
	}{
		{"https://api.acme.com/v1/x", true},
		{"https://api.acme.com:443/", true},
		{"http://api.acme.com/", false},       // scheme mismatch
		{"https://api.acme.com:9999/", false}, // undeclared port
		{"https://sub.acme.com:8443/x", true}, // wildcard
		{"https://a.b.acme.com:8443/", true},  // wildcard, nested
		{"https://acme.com/", false},          // *.acme.com does not match the apex
		{"https://evilacme.com/", false},      // suffix-sharing sibling
		{"https://sub.evilacme.com:8443/", false},
		{"http://192.0.2.10/", true},   // declared IP literal
		{"http://192.0.2.11/", false},  // undeclared IP
		{"https://192.0.2.10/", false}, // scheme mismatch on IP
	}
	for _, c := range cases {
		u, err := url.Parse(c.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", c.raw, err)
		}
		if got := p.Declared(u); got != c.want {
			t.Errorf("Declared(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestParse_RejectsBadEntries(t *testing.T) {
	for _, raw := range []string{
		"ftp://example.com", "example.com", "https://", "https://example.com/path",
		"https://user:pass@example.com", "https://example.com?x=1", "https://2130706433",
	} {
		if _, err := Parse(raw, false); err == nil {
			t.Errorf("Parse(%q) should fail", raw)
		}
	}
	if p, err := Parse("  https://a.com , https://b.com ", false); err != nil || len(p.patterns) != 2 {
		t.Errorf("whitespace around entries should be trimmed, got %v %v", p, err)
	}
	if p, err := Parse("", false); err != nil || len(p.patterns) != 0 {
		t.Errorf("empty allow-list should parse to a deny-all policy, got %v %v", p, err)
	}
}

func TestCheckURL_RejectsUserinfo(t *testing.T) {
	p, _ := Parse("http://example.com", false)
	u, _ := url.Parse("http://user:pass@example.com/x")
	if err := p.checkURL(u); err == nil || !strings.Contains(err.Error(), "userinfo") {
		t.Fatalf("userinfo url should be denied, got %v", err)
	}
}

func TestCheckURL_RejectsNonCanonicalHosts(t *testing.T) {
	// Decimal, octal and hex IP encodings of 127.0.0.1 must not sneak through
	// the allow-list as a "hostname".
	for _, host := range []string{"2130706433", "0177.0.0.1", "0x7f000001", "0x7f.0.0.1"} {
		if _, err := Parse("http://"+host, false); err == nil {
			t.Errorf("allow-list entry with non-canonical host %q should fail to parse", host)
		}
	}
}

func TestCheckIP(t *testing.T) {
	deniedByDefault := []string{
		"127.0.0.1", "127.8.8.8", "::1", // loopback
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // private
		"169.254.0.5", "fe80::1", // link-local
		"100.64.0.1", "64:ff9b::7f00:1", // CGNAT / NAT64
		"fc00::1",                                             // ULA
		"169.254.169.254", "fd00:ec2::254", "100.100.100.200", // metadata
		"0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255", // reserved/multicast/broadcast
		"192.0.2.1", "198.51.100.1", "203.0.113.1", // documentation
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", // v4-mapped private
	}
	for _, s := range deniedByDefault {
		if err := (&Policy{}).checkIP(netip.MustParseAddr(s)); err == nil {
			t.Errorf("%s should be denied by default", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8"} {
		if err := (&Policy{}).checkIP(netip.MustParseAddr(s)); err != nil {
			t.Errorf("public %s should be allowed: %v", s, err)
		}
	}
	// AllowPrivate is the stronger local policy: it permits private/loopback/
	// link-local, but metadata and reserved ranges stay blocked.
	p := &Policy{AllowPrivate: true}
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.0.5", "fc00::1", "100.64.0.1"} {
		if err := p.checkIP(netip.MustParseAddr(s)); err != nil {
			t.Errorf("AllowPrivate should permit %s: %v", s, err)
		}
	}
	for _, s := range []string{"169.254.169.254", "fd00:ec2::254", "100.100.100.200", "0.0.0.0", "224.0.0.1"} {
		if err := p.checkIP(netip.MustParseAddr(s)); err == nil {
			t.Errorf("%s must stay blocked even with AllowPrivate", s)
		}
	}
}
