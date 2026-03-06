package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/Resinat/Resin/internal/netutil"
	"github.com/Resinat/Resin/internal/outbound"
	"github.com/Resinat/Resin/internal/routing"
	M "github.com/sagernet/sing/common/metadata"
)

// SOCKS5 protocol constants (RFC 1928 / 1929).
const (
	socks5Version          = 0x05
	socks5AuthNone         = 0x00
	socks5AuthUserPass     = 0x02
	socks5AuthNoAcceptable = 0xFF
	socks5CmdConnect       = 0x01
	socks5AddrIPv4         = 0x01
	socks5AddrDomain       = 0x03
	socks5AddrIPv6         = 0x04
	socks5RepSuccess       = 0x00
	socks5RepGeneralFail   = 0x01
	socks5RepConnNotAllowed = 0x02
	socks5RepHostUnreach   = 0x04
	socks5RepConnRefused   = 0x05
	socks5RepCmdNotSupp    = 0x07
	socks5RepAddrNotSupp   = 0x08
	socks5UserPassVersion  = 0x01
)

// Socks5Config holds dependencies for the SOCKS5 inbound proxy.
type Socks5Config struct {
	ProxyToken  string
	Router      *routing.Router
	Pool        outbound.PoolAccessor
	Health      HealthRecorder
	Events      EventEmitter
	MetricsSink MetricsEventSink
}

// Socks5Server implements an inbound SOCKS5 proxy server.
type Socks5Server struct {
	token       string
	router      *routing.Router
	pool        outbound.PoolAccessor
	health      HealthRecorder
	events      EventEmitter
	metricsSink MetricsEventSink
}

// NewSocks5Server creates a new SOCKS5 inbound proxy server.
func NewSocks5Server(cfg Socks5Config) *Socks5Server {
	ev := cfg.Events
	if ev == nil {
		ev = NoOpEventEmitter{}
	}
	return &Socks5Server{
		token:       cfg.ProxyToken,
		router:      cfg.Router,
		pool:        cfg.Pool,
		health:      cfg.Health,
		events:      ev,
		metricsSink: cfg.MetricsSink,
	}
}

// HandleConn handles a single inbound SOCKS5 connection.
// It runs the full SOCKS5 handshake, authenticates, resolves routing,
// dials the outbound, and runs the bidirectional tunnel.
// The caller must close conn after HandleConn returns.
func (s *Socks5Server) HandleConn(conn net.Conn) {
	ctx := context.Background()
	// Set a generous handshake deadline; cleared once tunnel starts.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// --- Phase 1: greeting ---
	platName, account, authErr := s.socks5Handshake(conn)
	if authErr != nil {
		return // handshake already wrote failure reply
	}

	// --- Phase 2: command request ---
	target, err := s.readCommandRequest(conn)
	if err != nil {
		return
	}

	// --- Phase 3: route & dial ---
	lifecycle := s.newSocks5Lifecycle(conn, target, account)
	defer lifecycle.finish()

	routed, routeErr := resolveRoutedOutbound(s.router, s.pool, platName, account, target)
	if routeErr != nil {
		lifecycle.setProxyError(routeErr)
		s.writeReply(conn, socks5RepGeneralFail)
		return
	}
	lifecycle.setRouteResult(routed.Route)

	domain := netutil.ExtractDomain(target)
	nodeHash := routed.Route.NodeHash
	go s.health.RecordLatency(nodeHash, domain, nil)

	// Clear handshake deadline before dialing upstream (upstream has its own timeout).
	_ = conn.SetDeadline(time.Time{})

	// --- Phase 3.5: SNI-based target rewrite for IP-only SOCKS5 clients ---
	// When the client uses socks5:// (not socks5h://), it resolves DNS locally
	// and sends a raw IP address. The upstream outbound receives the IP and
	// forwards it to the exit node, but the exit node may need a domain name
	// (e.g. for TLS SNI, virtual hosting, or proper DNS at the exit).
	//
	// To fix this, we send the SOCKS5 success reply first (so the client
	// proceeds with TLS), peek the TLS ClientHello, extract the SNI domain,
	// and use that domain (with the original port) as the upstream dial target.
	// The peeked bytes are then replayed to the tunnel.
	dialTarget := target
	var peekedClientData []byte
	host, port, _ := net.SplitHostPort(target)
	targetIsIP := net.ParseIP(host) != nil

	if targetIsIP {
		// Send success reply early so the client starts TLS handshake.
		s.writeReply(conn, socks5RepSuccess)

		// Peek the first chunk from the client (expected: TLS ClientHello).
		peekBuf := make([]byte, 16384)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, peekErr := conn.Read(peekBuf)
		_ = conn.SetReadDeadline(time.Time{})

		if n > 0 {
			peekedClientData = peekBuf[:n]
			if sni, ok := extractSNI(peekedClientData); ok {
				dialTarget = net.JoinHostPort(sni, port)
				// Update lifecycle/domain for logging.
				lifecycle.log.TargetHost = dialTarget
				domain = netutil.ExtractDomain(dialTarget)
			}
		}
		if peekErr != nil && n == 0 {
			// No data from client at all — cannot proceed.
			lifecycle.setProxyError(ErrUpstreamRequestFailed)
			lifecycle.setUpstreamError("socks5_sni_peek", peekErr)
			go s.health.RecordResult(nodeHash, false)
			return
		}
	}

	rawConn, dialErr := routed.Outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(dialTarget))
	if dialErr != nil {
		proxyErr := classifyConnectError(dialErr)
		if proxyErr == nil {
			// context.Canceled — benign client disconnect.
			lifecycle.setNetOK(true)
			if !targetIsIP {
				s.writeReply(conn, socks5RepGeneralFail)
			}
			return
		}
		lifecycle.setProxyError(proxyErr)
		lifecycle.setUpstreamError("socks5_dial", dialErr)
		go s.health.RecordResult(nodeHash, false)
		if !targetIsIP {
			s.writeReply(conn, socks5RepHostUnreach)
		}
		return
	}

	// Wrap upstream connection for metrics.
	var upstreamConn net.Conn = rawConn
	if s.metricsSink != nil {
		s.metricsSink.OnConnectionLifecycle(ConnectionOutbound, ConnectionOpen)
		upstreamConn = newCountingConn(rawConn, s.metricsSink)
	}

	// Wrap with TLS latency measurement.
	upstreamConn = newTLSLatencyConn(upstreamConn, func(latency time.Duration) {
		s.health.RecordLatency(nodeHash, domain, &latency)
	})

	// --- Phase 4: send success reply (if not already sent for SNI peek) ---
	if !targetIsIP {
		s.writeReply(conn, socks5RepSuccess)
	}

	// --- Phase 5: early handshake for lazy/early conns ---
	// sing-box outbounds (SS, VLESS, etc.) return "early conns" that defer
	// protocol headers until the first Write(). We must trigger the handshake
	// before starting concurrent bidirectional copy, otherwise the Read side
	// may race ahead of Write and fail (no server response because no request
	// was sent yet).
	//
	// If we already peeked client data (SNI rewrite path), replay it to
	// upstream first — this serves as the early handshake trigger.
	var clientReader io.Reader = conn
	if len(peekedClientData) > 0 {
		// Write the peeked ClientHello to upstream.
		if _, writeErr := upstreamConn.Write(peekedClientData); writeErr != nil {
			lifecycle.setProxyError(ErrUpstreamRequestFailed)
			lifecycle.setUpstreamError("socks5_sni_replay", writeErr)
			go s.health.RecordResult(nodeHash, false)
			return
		}
		// Skip the normal early handshake — we've already triggered it.
	} else {
		var earlyErr error
		clientReader, earlyErr = performEarlyHandshake(conn, conn, upstreamConn)
		if earlyErr != nil {
			lifecycle.setProxyError(ErrUpstreamRequestFailed)
			lifecycle.setUpstreamError("socks5_early_handshake", earlyErr)
			go s.health.RecordResult(nodeHash, false)
			return
		}
	}

	// --- Phase 6: bidirectional tunnel ---
	recordResult := func(ok bool) {
		lifecycle.setNetOK(ok)
		go s.health.RecordResult(nodeHash, ok)
	}

	type copyResult struct {
		n   int64
		err error
	}
	egressBytesCh := make(chan copyResult, 1)
	go func() {
		defer upstreamConn.Close()
		defer conn.Close()
		n, copyErr := io.Copy(upstreamConn, clientReader)
		egressBytesCh <- copyResult{n: n, err: copyErr}
	}()
	ingressBytes, ingressCopyErr := io.Copy(conn, upstreamConn)
	lifecycle.addIngressBytes(ingressBytes)
	conn.Close()
	upstreamConn.Close()
	egressResult := <-egressBytesCh
	lifecycle.addEgressBytes(egressResult.n)

	okResult := ingressBytes > 0 && egressResult.n > 0
	if !okResult {
		lifecycle.setProxyError(ErrUpstreamRequestFailed)
		switch {
		case !isBenignTunnelCopyError(ingressCopyErr):
			lifecycle.setUpstreamError("socks5_upstream_to_client_copy", ingressCopyErr)
		case !isBenignTunnelCopyError(egressResult.err):
			lifecycle.setUpstreamError("socks5_client_to_upstream_copy", egressResult.err)
		default:
			switch {
			case ingressBytes == 0 && egressResult.n == 0:
				lifecycle.setUpstreamError("socks5_zero_traffic", nil)
			case ingressBytes == 0:
				lifecycle.setUpstreamError("socks5_no_ingress_traffic", nil)
			default:
				lifecycle.setUpstreamError("socks5_no_egress_traffic", nil)
			}
		}
	}
	recordResult(okResult)
}

// socks5Handshake performs greeting + authentication and returns
// (platformName, account, error).
func (s *Socks5Server) socks5Handshake(conn net.Conn) (string, string, error) {
	// Read greeting: VER, NMETHODS, METHODS...
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", "", err
	}
	if buf[0] != socks5Version {
		return "", "", fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", "", err
	}

	// When token is empty, auth is disabled — accept "no auth" or "user/pass".
	if s.token == "" {
		// Prefer user/pass if offered (to extract platform identity).
		hasUserPass := false
		hasNone := false
		for _, m := range methods {
			if m == socks5AuthUserPass {
				hasUserPass = true
			}
			if m == socks5AuthNone {
				hasNone = true
			}
		}
		if hasUserPass {
			// Negotiate user/pass to extract identity.
			if _, err := conn.Write([]byte{socks5Version, socks5AuthUserPass}); err != nil {
				return "", "", err
			}
			platName, account, err := s.readUserPassSubnegotiation(conn, false)
			if err != nil {
				return "", "", err
			}
			return platName, account, nil
		}
		if hasNone {
			if _, err := conn.Write([]byte{socks5Version, socks5AuthNone}); err != nil {
				return "", "", err
			}
			return "", "", nil
		}
		// No acceptable method.
		_, _ = conn.Write([]byte{socks5Version, socks5AuthNoAcceptable})
		return "", "", errors.New("no acceptable auth method")
	}

	// Token is set — require user/pass auth.
	hasUserPass := false
	for _, m := range methods {
		if m == socks5AuthUserPass {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		_, _ = conn.Write([]byte{socks5Version, socks5AuthNoAcceptable})
		return "", "", errors.New("client does not support username/password auth")
	}

	if _, err := conn.Write([]byte{socks5Version, socks5AuthUserPass}); err != nil {
		return "", "", err
	}

	platName, account, err := s.readUserPassSubnegotiation(conn, true)
	if err != nil {
		return "", "", err
	}
	return platName, account, nil
}

// readUserPassSubnegotiation reads RFC 1929 username/password subnegotiation.
// When requireToken is true, username must match s.token.
// Returns (platformName, account, error).
func (s *Socks5Server) readUserPassSubnegotiation(conn net.Conn, requireToken bool) (string, string, error) {
	// VER (1 byte) | ULEN (1 byte) | UNAME (ULEN bytes) | PLEN (1 byte) | PASSWD (PLEN bytes)
	verBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, verBuf); err != nil {
		return "", "", err
	}
	if verBuf[0] != socks5UserPassVersion {
		// Write auth failure reply.
		_, _ = conn.Write([]byte{socks5UserPassVersion, 0x01})
		return "", "", fmt.Errorf("unsupported user/pass version: %d", verBuf[0])
	}
	uLen := int(verBuf[1])
	uname := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return "", "", err
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return "", "", err
	}
	pLen := int(pLenBuf[0])
	passwd := make([]byte, pLen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return "", "", err
	}

	username := string(uname)
	password := string(passwd)

	if requireToken {
		if username != s.token {
			// Write auth failure reply.
			_, _ = conn.Write([]byte{socks5UserPassVersion, 0x01})
			return "", "", errors.New("socks5 auth: invalid token")
		}
	}

	// Write auth success reply.
	if _, err := conn.Write([]byte{socks5UserPassVersion, 0x00}); err != nil {
		return "", "", err
	}

	// Password carries "Platform:Account" identity.
	platName, account := parsePlatformAccount(password)
	return platName, account, nil
}

// readCommandRequest reads the SOCKS5 command request and returns the
// target address in host:port form. Only CONNECT (0x01) is supported.
func (s *Socks5Server) readCommandRequest(conn net.Conn) (string, error) {
	// VER (1) | CMD (1) | RSV (1) | ATYP (1)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != socks5Version {
		s.writeReply(conn, socks5RepGeneralFail)
		return "", fmt.Errorf("version mismatch in command: %d", header[0])
	}
	if header[1] != socks5CmdConnect {
		s.writeReply(conn, socks5RepCmdNotSupp)
		return "", fmt.Errorf("unsupported command: %d", header[1])
	}

	atyp := header[3]
	var host string
	switch atyp {
	case socks5AddrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	case socks5AddrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()
	case socks5AddrDomain:
		domLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, domLenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, domLenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
	default:
		s.writeReply(conn, socks5RepAddrNotSupp)
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// writeReply sends a minimal SOCKS5 reply with the given status code.
// The bound address is always 0.0.0.0:0.
func (s *Socks5Server) writeReply(conn net.Conn, rep byte) {
	// VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(4 for IPv4) BND.PORT(2) = 10 bytes
	reply := []byte{
		socks5Version,
		rep,
		0x00,          // RSV
		socks5AddrIPv4, // ATYP
		0, 0, 0, 0,   // BND.ADDR
		0, 0,          // BND.PORT
	}
	_, _ = conn.Write(reply)
}

// newSocks5Lifecycle creates a requestLifecycle for SOCKS5 connections.
// Since SOCKS5 is not HTTP, we construct the lifecycle manually.
func (s *Socks5Server) newSocks5Lifecycle(conn net.Conn, target, account string) *requestLifecycle {
	clientIP := ""
	if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		clientIP = host
	} else {
		clientIP = conn.RemoteAddr().String()
	}

	now := time.Now()
	lc := &requestLifecycle{
		startedAt: now,
		events:    s.events,
		finished: RequestFinishedEvent{
			ProxyType: ProxyTypeSocks5,
			IsConnect: true,
		},
		log: RequestLogEntry{
			StartedAtNs: now.UnixNano(),
			ProxyType:   ProxyTypeSocks5,
			ClientIP:    clientIP,
			HTTPMethod:  "SOCKS5-CONNECT",
			TargetHost:  target,
			Account:     account,
		},
	}
	return lc
}
