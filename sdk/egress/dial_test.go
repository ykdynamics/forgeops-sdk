package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestDialContext_PinsResolvedAddress(t *testing.T) {
	// The connection must go to the pinned validated address, not a
	// re-resolved hostname — there is no second resolution to rebind.
	p := &Policy{}
	p.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "api.example.com" {
			t.Errorf("resolved host = %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("2606:2800::1")}, nil
	}
	var dialed string
	p.dial = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		return nil, errors.New("stop here")
	}
	_, err := p.dialContext(context.Background(), "tcp", "api.example.com:443")
	if err == nil || !strings.Contains(err.Error(), "stop here") {
		t.Fatalf("want the dial error, got %v", err)
	}
	if dialed != "93.184.216.34:443" {
		t.Errorf("dialed %q, want the pinned resolved address", dialed)
	}
}

func TestDialContext_ResolvesExactlyOnce(t *testing.T) {
	p := &Policy{AllowPrivate: true}
	calls := 0
	p.resolve = func(_ context.Context, _ string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	p.dial = func(_ context.Context, _, _ string) (net.Conn, error) { return nil, errors.New("stop") }
	_, _ = p.dialContext(context.Background(), "tcp", "api.example.com:80")
	if calls != 1 {
		t.Errorf("resolved %d times, want exactly 1 (single resolution is the rebinding defense)", calls)
	}
}

func TestDialContext_FailsClosedOnMixedResolvedSet(t *testing.T) {
	// One public + one private address: the whole set is denied, because the
	// connection could be steered to the private address.
	p := &Policy{}
	p.resolve = func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	_, err := p.dialContext(context.Background(), "tcp", "api.example.com:443")
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("mixed resolved set must fail closed, got %v", err)
	}
}

func TestDialContext_DeniesBlockedIPLiteral(t *testing.T) {
	p := &Policy{}
	if _, err := p.dialContext(context.Background(), "tcp", "127.0.0.1:80"); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("loopback literal should be denied, got %v", err)
	}
	// Metadata literal stays denied even under AllowPrivate.
	p = &Policy{AllowPrivate: true}
	if _, err := p.dialContext(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Fatal("metadata literal must be denied even with AllowPrivate")
	}
}
