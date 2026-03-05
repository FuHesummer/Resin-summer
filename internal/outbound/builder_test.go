package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Resinat/Resin/internal/testutil"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// ---------------------------------------------------------------------------
// SingboxBuilder constructor / teardown
// ---------------------------------------------------------------------------

func TestNewSingboxBuilder(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("SingboxBuilder.Close() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Build: parse and create real outbound
// ---------------------------------------------------------------------------

func TestSingboxBuilder_ParseShadowsocks(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	raw := json.RawMessage(`{
		"type": "shadowsocks",
		"tag":  "test-ss",
		"server": "127.0.0.1",
		"server_port": 8388,
		"method": "aes-256-gcm",
		"password": "test-password"
	}`)
	ob, err := b.Build(raw, nil)
	if err != nil {
		t.Fatalf("Build(shadowsocks) error: %v", err)
	}

	// Should implement io.Closer (sing-box outbounds do)
	closer, ok := ob.(io.Closer)
	if !ok {
		t.Fatal("expected outbound to implement io.Closer")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("outbound Close() error: %v", err)
	}
}

func TestSingboxBuilder_ParseExtendedProtocols(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	cases := []struct {
		name               string
		raw                json.RawMessage
		missingFeatureHint string
	}{
		{
			name: "socks",
			raw: json.RawMessage(`{
				"type":"socks",
				"tag":"test-socks",
				"server":"127.0.0.1",
				"server_port":1080,
				"version":"5",
				"username":"user",
				"password":"pass"
			}`),
		},
		{
			name: "http",
			raw: json.RawMessage(`{
				"type":"http",
				"tag":"test-http",
				"server":"127.0.0.1",
				"server_port":8080,
				"username":"user",
				"password":"pass"
			}`),
		},
		{
			name: "wireguard",
			raw: json.RawMessage(`{
				"type":"wireguard",
				"tag":"test-wg",
				"server":"127.0.0.1",
				"server_port":2480,
				"local_address":["172.16.0.2/32","fd01::1/128"],
				"private_key":"eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=",
				"peer_public_key":"Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo="
			}`),
			missingFeatureHint: "WireGuard is not included in this build",
		},
		{
			name: "hysteria",
			raw: json.RawMessage(`{
				"type":"hysteria",
				"tag":"test-hysteria",
				"server":"127.0.0.1",
				"server_port":443,
				"auth_str":"password",
				"up_mbps":30,
				"down_mbps":200,
				"tls":{"enabled":true,"insecure":true,"server_name":"example.com"}
			}`),
			missingFeatureHint: "QUIC is not included in this build",
		},
		{
			name: "tuic",
			raw: json.RawMessage(`{
				"type":"tuic",
				"tag":"test-tuic",
				"server":"127.0.0.1",
				"server_port":443,
				"uuid":"00000000-0000-0000-0000-000000000001",
				"password":"password",
				"tls":{"enabled":true,"insecure":true,"server_name":"example.com"}
			}`),
			missingFeatureHint: "QUIC is not included in this build",
		},
		{
			name: "anytls",
			raw: json.RawMessage(`{
				"type":"anytls",
				"tag":"test-anytls",
				"server":"127.0.0.1",
				"server_port":443,
				"password":"password",
				"tls":{"enabled":true,"insecure":true,"server_name":"example.com"}
			}`),
		},
		{
			name: "ssh",
			raw: json.RawMessage(`{
				"type":"ssh",
				"tag":"test-ssh",
				"server":"127.0.0.1",
				"server_port":22,
				"user":"root",
				"password":"password"
			}`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ob, err := b.Build(tc.raw, nil)
			if err != nil {
				if tc.missingFeatureHint != "" && strings.Contains(err.Error(), tc.missingFeatureHint) {
					t.Skipf("skipping %s: %v", tc.name, err)
					return
				}
				t.Fatalf("Build(%s) error: %v", tc.name, err)
			}
			if ob == nil {
				t.Fatalf("Build(%s) returned nil outbound", tc.name)
			}
			if closer, ok := ob.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					t.Fatalf("Build(%s) outbound Close() error: %v", tc.name, err)
				}
			}
		})
	}
}

func TestSingboxBuilder_UnknownType(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	raw := json.RawMessage(`{"type": "totally-fake-protocol-xyz", "tag": "x"}`)
	_, err = b.Build(raw, nil)
	if err == nil {
		t.Fatal("expected error for unknown outbound type, got nil")
	}
}

func TestSingboxBuilder_InvalidJSON(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	raw := json.RawMessage(`{invalid`)
	_, err = b.Build(raw, nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestStubOutboundBuilder_Build(t *testing.T) {
	ob, err := (&testutil.StubOutboundBuilder{}).Build(nil, nil)
	if err != nil {
		t.Fatalf("StubOutboundBuilder.Build() error: %v", err)
	}
	if ob == nil {
		t.Fatal("expected non-nil outbound")
	}
	if ob.Type() != "stub" {
		t.Fatalf("unexpected outbound type: %s", ob.Type())
	}
}

// ---------------------------------------------------------------------------
// Relay chain: SS with detour → VLESS dependency bundle
// ---------------------------------------------------------------------------

func TestSingboxBuilder_RelayChain_SS_Detour_VLESS(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	// Main outbound: Shadowsocks with detour pointing to a VLESS relay tag.
	ssRaw := json.RawMessage(`{
		"type": "shadowsocks",
		"tag":  "ss-landing",
		"server": "us-shop.example.net",
		"server_port": 10002,
		"method": "aes-256-gcm",
		"password": "test-password",
		"detour": "relay-vless"
	}`)

	// Dependency bundle: VLESS relay outbound that the SS detour references.
	depBundle := json.RawMessage(`{
		"outbounds": [{
			"type": "vless",
			"tag":  "relay-vless",
			"server": "38.246.237.64",
			"server_port": 443,
			"uuid": "00000000-0000-0000-0000-000000000001",
			"tls": {
				"enabled": true,
				"server_name": "example.com",
				"insecure": true
			}
		}]
	}`)

	ob, err := b.Build(ssRaw, depBundle)
	if err != nil {
		t.Fatalf("Build(SS+VLESS relay chain) error: %v", err)
	}
	if ob == nil {
		t.Fatal("Build returned nil outbound")
	}
	t.Logf("relay chain outbound type=%s tag=%s", ob.Type(), ob.Tag())

	// With the isolated-manager fix, dependencies are NOT in the shared
	// outboundMgr. They live in a per-Build isolated manager, which is
	// correct — it prevents tag collision across nodes.

	// Clean up.
	if closer, ok := ob.(io.Closer); ok {
		_ = closer.Close()
	}
}

// TestSingboxBuilder_RelayChain_SS_Detour_VLESS_WithTransport tests relay chain
// with VLESS using WebSocket transport (common in real configs).
func TestSingboxBuilder_RelayChain_SS_Detour_VLESS_WithTransport(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	ssRaw := json.RawMessage(`{
		"type": "shadowsocks",
		"tag":  "ss-landing-ws",
		"server": "us-shop.example.net",
		"server_port": 10002,
		"method": "aes-256-gcm",
		"password": "test-password",
		"detour": "relay-vless-ws"
	}`)

	depBundle := json.RawMessage(`{
		"outbounds": [{
			"type": "vless",
			"tag":  "relay-vless-ws",
			"server": "38.246.237.64",
			"server_port": 443,
			"uuid": "00000000-0000-0000-0000-000000000001",
			"tls": {
				"enabled": true,
				"server_name": "example.com",
				"insecure": true,
				"utls": {
					"enabled": true,
					"fingerprint": "chrome"
				}
			},
			"transport": {
				"type": "ws",
				"path": "/ws-path",
				"headers": {
					"Host": "example.com"
				}
			}
		}]
	}`)

	ob, err := b.Build(ssRaw, depBundle)
	if err != nil {
		if strings.Contains(err.Error(), "uTLS is not included") {
			t.Skipf("skipping: %v", err)
		}
		t.Fatalf("Build(SS+VLESS-WS relay chain) error: %v", err)
	}
	if ob == nil {
		t.Fatal("Build returned nil outbound")
	}
	t.Logf("relay chain WS outbound type=%s tag=%s", ob.Type(), ob.Tag())

	if closer, ok := ob.(io.Closer); ok {
		_ = closer.Close()
	}
}

// ---------------------------------------------------------------------------
// CAS loser close
// ---------------------------------------------------------------------------

// closableBuilder builds closable outbounds that track Close() calls.
type closableBuilder struct {
	mu    sync.Mutex
	built []*trackCloser
}

type trackCloser struct {
	closed atomic.Bool
}

func (c *trackCloser) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *trackCloser) Type() string {
	return "track-closer"
}

func (c *trackCloser) Tag() string {
	return "track-closer"
}

func (c *trackCloser) Network() []string {
	return []string{"tcp", "udp"}
}

func (c *trackCloser) Dependencies() []string {
	return nil
}

func (c *trackCloser) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("track-closer: dial not supported")
}

func (c *trackCloser) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("track-closer: listen packet not supported")
}

func (b *closableBuilder) Build(_ json.RawMessage, _ json.RawMessage) (adapter.Outbound, error) {
	tc := &trackCloser{}
	b.mu.Lock()
	b.built = append(b.built, tc)
	b.mu.Unlock()
	return tc, nil
}

func TestEnsureNodeOutbound_CASLoserClose(t *testing.T) {
	entry := newTestEntry(`{"type":"test"}`)
	pool := &mockPool{}
	pool.addEntry(entry)

	cb := &closableBuilder{}
	mgr := NewOutboundManager(pool, cb)

	// Run many concurrent EnsureNodeOutbound calls. Only the CAS winner's
	// outbound survives; all losers must be closed.
	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			mgr.EnsureNodeOutbound(entry.Hash)
		}()
	}
	wg.Wait()

	if entry.Outbound.Load() == nil {
		t.Fatal("expected outbound to be set")
	}

	cb.mu.Lock()
	total := len(cb.built)
	closedCount := 0
	for _, tc := range cb.built {
		if tc.closed.Load() {
			closedCount++
		}
	}
	cb.mu.Unlock()

	// With N concurrent goroutines, some pass the fast-path nil check before
	// the winner's CAS succeeds. Those losers must all be closed.
	if total > 1 && closedCount != total-1 {
		t.Errorf("expected %d closed outbounds, got %d (total built: %d)", total-1, closedCount, total)
	}
}

// ---------------------------------------------------------------------------
// Remove close
// ---------------------------------------------------------------------------

func TestRemoveNodeOutbound_Closes(t *testing.T) {
	tc := &trackCloser{}
	entry := newTestEntry(`{"type":"test"}`)
	var wrapped adapter.Outbound = tc
	entry.Outbound.Store(&wrapped)

	pool := &mockPool{}
	mgr := NewOutboundManager(pool, &testutil.StubOutboundBuilder{})

	mgr.RemoveNodeOutbound(entry)

	if !tc.closed.Load() {
		t.Fatal("expected outbound to be closed after RemoveNodeOutbound")
	}
	if entry.Outbound.Load() != nil {
		t.Fatal("expected outbound to be nil after RemoveNodeOutbound")
	}
}
