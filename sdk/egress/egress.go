// Package egress implements a deny-by-default outbound HTTP policy for
// capabilities. A capability reaches only destinations that
// are declared in its allow-list, over addresses that are validated at
// connection time, and never forwards credentials across an authority change.
//
// The security properties, and where each is enforced:
//
//   - Declared destinations only. The allow-list is the declared
//     scheme/host/port policy; anything else is denied at request time
//     (checkURL in the RoundTripper).
//   - Every resolved address is validated at connection time. A hostname is
//     resolved exactly once, every returned address must pass the IP policy,
//     and the connection is made to the pinned validated address — never by
//     re-resolving the hostname — so DNS rebinding cannot swap a validated
//     name for a private one after the check.
//   - Redirects are revalidated. Each redirect authority must be declared and
//     passes the same connection-time checks; on any authority change all
//     caller-supplied headers are dropped so injected credentials cannot be
//     forwarded to a different destination.
//   - Blocked ranges. Loopback, link-local, private, CGNAT, ULA, multicast,
//     reserved and documentation ranges are denied unless AllowPrivate is set
//     (the stronger local policy). Cloud metadata endpoints are always denied.
//   - Safe normalization. URLs carrying userinfo are rejected, and non-canonical
//     hosts (decimal/octal/hex IP encodings) are refused.
package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Pattern is one declared destination: a scheme, a host (optionally a "*."
// wildcard prefix), and an effective port.
type Pattern struct {
	scheme string
	host   string
	port   int
}

// Policy is a deny-by-default egress policy. An empty allow-list denies every
// destination. AllowPrivate is the stronger local policy that permits
// private/loopback/link-local/CGNAT/ULA ranges (for an in-cluster service or
// a test harness); metadata and reserved ranges are never reachable.
type Policy struct {
	patterns     []Pattern
	AllowPrivate bool

	// resolve and dial are injectable seams for deterministic tests: resolve
	// returns every address of a hostname at connection time, and dial makes
	// the connection to the pinned validated address.
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Parse builds a Policy from a comma-separated allow-list of scheme://host[:port]
// patterns and the allow-private flag. An empty allow-list denies all egress.
func Parse(allowlist string, allowPrivate bool) (*Policy, error) {
	p := &Policy{AllowPrivate: allowPrivate}
	for _, raw := range strings.Split(allowlist, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		pat, err := parsePattern(raw)
		if err != nil {
			return nil, err
		}
		p.patterns = append(p.patterns, pat)
	}
	return p, nil
}

func parsePattern(raw string) (Pattern, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Pattern{}, fmt.Errorf("egress: invalid allow-list entry %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Pattern{}, fmt.Errorf("egress: allow-list entry %q: scheme must be http or https", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Pattern{}, fmt.Errorf("egress: allow-list entry %q: userinfo/query/fragment are not allowed", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return Pattern{}, fmt.Errorf("egress: allow-list entry %q: path is not allowed", raw)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return Pattern{}, fmt.Errorf("egress: allow-list entry %q: empty host", raw)
	}
	if err := validateHost(host); err != nil {
		return Pattern{}, fmt.Errorf("egress: allow-list entry %q: %w", raw, err)
	}
	port, err := effectivePort(u)
	if err != nil {
		return Pattern{}, fmt.Errorf("egress: allow-list entry %q: %w", raw, err)
	}
	return Pattern{scheme: u.Scheme, host: host, port: port}, nil
}

// Declared reports whether u's authority is covered by the allow-list.
func (p *Policy) Declared(u *url.URL) bool {
	if p == nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || validateHost(host) != nil {
		return false
	}
	port, err := effectivePort(u)
	if err != nil {
		return false
	}
	for _, pat := range p.patterns {
		if pat.scheme != u.Scheme || pat.port != port {
			continue
		}
		if hostMatches(pat.host, host) {
			return true
		}
	}
	return false
}

// hostMatches matches an exact host or a "*.domain" wildcard (subdomains only;
// a bare "domain" does not match "*.domain").
func hostMatches(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return pattern == host
}

// effectivePort returns the explicit port of u, or the scheme's default.
func effectivePort(u *url.URL) (int, error) {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("invalid port %q", p)
		}
		return n, nil
	}
	switch u.Scheme {
	case "http":
		return 80, nil
	case "https":
		return 443, nil
	}
	return 0, fmt.Errorf("unsupported scheme %q", u.Scheme)
}

// validateHost rejects non-canonical hosts: anything that is neither a
// canonical IP literal (netip) nor a plain DNS hostname. This refuses
// decimal/octal/hex IP encodings such as "2130706433", "0177.0.0.1" and
// "0x7f000001", which would otherwise smuggle a private address past the
// allow-list.
func validateHost(host string) error {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "*."), ".")
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if len(host) > 253 {
		return fmt.Errorf("host too long")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil // canonical IP literal
	}
	allNumeric := true
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label too long")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label must not start or end with a hyphen")
		}
		if len(label) > 2 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X') {
			return fmt.Errorf("hex-prefixed label looks like an IP-encoding trick")
		}
		numeric := true
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
				if c < '0' || c > '9' {
					numeric = false
				}
			default:
				return fmt.Errorf("invalid character %q in host", c)
			}
		}
		if !numeric {
			allNumeric = false
		}
	}
	if allNumeric {
		return fmt.Errorf("all-numeric host looks like an IP-encoding trick")
	}
	return nil
}

// IP ranges that are never reachable, even under AllowPrivate: reserved,
// multicast, broadcast, documentation, and the well-known cloud metadata
// endpoints (AWS/GCP/Azure IMDS, AWS IMDSv2 IPv6, Alibaba IMDS).
var alwaysBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),       // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),        // multicast
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved
	netip.MustParsePrefix("255.255.255.255/32"), // broadcast
	netip.MustParsePrefix("::/128"),             // unspecified
	netip.MustParsePrefix("ff00::/8"),           // multicast
	netip.MustParsePrefix("169.254.169.254/32"), // cloud metadata (AWS/GCP/Azure)
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IMDSv2 IPv6
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba metadata
}

// IP ranges that are denied by default but permitted under the stronger local
// policy (AllowPrivate): loopback, link-local, private, CGNAT, NAT64, ULA.
var privateByDefault = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 well-known prefix
	netip.MustParsePrefix("fc00::/7"),       // ULA
	netip.MustParsePrefix("fe80::/10"),      // link-local v6
	netip.MustParsePrefix("::1/128"),        // loopback v6
}

// checkIP applies the IP policy to one address. IPv4-mapped IPv6 addresses are
// unmapped first so the embedded address is judged by the same rules.
func (p *Policy) checkIP(a netip.Addr) error {
	if p == nil {
		return fmt.Errorf("no egress policy configured")
	}
	a = a.Unmap()
	for _, pre := range alwaysBlocked {
		if pre.Contains(a) {
			return fmt.Errorf("address %s is blocked (reserved, multicast or metadata)", a)
		}
	}
	if !p.AllowPrivate {
		for _, pre := range privateByDefault {
			if pre.Contains(a) {
				return fmt.Errorf("address %s is in a private/loopback/link-local range", a)
			}
		}
	}
	return nil
}

// checkURL validates a request URL before it is sent: http/https scheme, no
// credentials in the URL, a canonical host, and a declared destination.
func (p *Policy) checkURL(u *url.URL) error {
	if p == nil {
		return fmt.Errorf("no egress policy configured")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("userinfo (credentials) in the url is not allowed")
	}
	host := strings.ToLower(u.Hostname())
	if err := validateHost(host); err != nil {
		return fmt.Errorf("non-canonical host %q: %w", host, err)
	}
	if !p.Declared(u) {
		return fmt.Errorf("destination %s is not declared in the egress allow-list", host)
	}
	return nil
}

// defaultResolve resolves a hostname to every address (the seams stay nil in
// production and are only injected by tests).
func (p *Policy) defaultResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ipa := range ips {
		if a, ok := netip.AddrFromSlice(ipa.IP); ok {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}

// dialContext is the connection-time enforcement point: resolve once, validate
// every resolved address, then dial the pinned validated address. Dialing by
// address (never by hostname) closes the DNS-rebinding window — there is no
// second resolution an attacker can answer differently.
func (p *Policy) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if p == nil {
		return nil, fmt.Errorf("egress: no policy configured")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("egress: split %q: %w", addr, err)
	}
	var target netip.Addr
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		target = a
	} else {
		resolve := p.resolve
		if resolve == nil {
			resolve = p.defaultResolve
		}
		all, err := resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("egress: resolve %s: %w", host, err)
		}
		if len(all) == 0 {
			return nil, fmt.Errorf("egress: %s resolves to no addresses", host)
		}
		for _, a := range all {
			if err := p.checkIP(a); err != nil {
				return nil, fmt.Errorf("egress: %s resolves to blocked address %s", host, a)
			}
		}
		target = all[0]
	}
	if err := p.checkIP(target); err != nil {
		return nil, fmt.Errorf("egress: %s: %w", host, err)
	}
	dialFn := p.dial
	if dialFn == nil {
		dialFn = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}
	return dialFn(ctx, network, net.JoinHostPort(target.String(), port))
}

// policyTransport enforces the URL policy on every request, including every
// redirect hop.
type policyTransport struct {
	base http.RoundTripper
	p    *Policy
}

func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.p.checkURL(req.URL); err != nil {
		return nil, fmt.Errorf("egress: %w", err)
	}
	return t.base.RoundTrip(req)
}

// Transport returns an http.RoundTripper enforcing this policy at request and
// connection time.
func (p *Policy) Transport() http.RoundTripper {
	if p == nil {
		p = &Policy{}
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DialContext = p.dialContext
	return &policyTransport{base: base, p: p}
}

// Client returns an http.Client that enforces p on every request and redirect.
// A nil policy denies all egress.
func Client(p *Policy, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport:     p.Transport(),
		CheckRedirect: p.CheckRedirect,
		Timeout:       timeout,
	}
}

// CheckRedirect revalidates every redirect: an authority change requires the
// new authority to be declared, and all caller-supplied headers are dropped so
// credentials injected for the original destination are never forwarded.
func (p *Policy) CheckRedirect(req *http.Request, via []*http.Request) error {
	if p == nil {
		return fmt.Errorf("egress: no policy configured")
	}
	if len(via) == 0 {
		return nil
	}
	if sameAuthority(req.URL, via[0].URL) {
		return nil
	}
	if err := p.checkURL(req.URL); err != nil {
		return fmt.Errorf("egress: redirect to %s denied: %w", req.URL.Host, err)
	}
	for k := range req.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		req.Header.Del(k)
	}
	return nil
}

// sameAuthority reports whether a and b share scheme, host and effective port.
func sameAuthority(a, b *url.URL) bool {
	if a.Scheme != b.Scheme {
		return false
	}
	pa, err1 := effectivePort(a)
	pb, err2 := effectivePort(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(a.Hostname(), b.Hostname()) && pa == pb
}
