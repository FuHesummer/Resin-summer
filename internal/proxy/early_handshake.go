package proxy

import (
	"io"
	"net"
	"time"

	N "github.com/sagernet/sing/common/network"
)

// earlyHandshakeTimeout is the maximum time to wait for the client to send
// the first data chunk (e.g. TLS ClientHello) before starting the tunnel.
// This mirrors sing-box's ConnectionManager.connectionCopyEarly behavior.
const earlyHandshakeTimeout = 300 * time.Millisecond

// earlyHandshakeResult holds the first data chunk read from the client
// during the early handshake phase, plus any error.
type earlyHandshakeResult struct {
	firstChunk []byte
	err        error
}

// performEarlyHandshake checks if upstreamConn is an early conn (lazy
// handshake) and, if so, reads the first data chunk from the client and
// writes it to upstream to trigger the protocol handshake.
//
// For early conns (e.g. Shadowsocks, VLESS), the protocol header is not
// sent until the first Write(). If we start bidirectional io.Copy without
// triggering the handshake first, the Read side races with the Write side:
// the upstream Read may execute before any Write has happened, causing the
// connection to fail (no response from server because no request was sent).
//
// This function returns a reader that should be used instead of the original
// clientReader for the client→upstream copy direction. It prepends any
// remaining buffered bytes that were not part of the first chunk.
//
// If the upstream is NOT an early conn, this function is a no-op and returns
// the original clientReader unchanged.
func performEarlyHandshake(
	clientConn net.Conn,
	clientReader io.Reader,
	upstreamConn net.Conn,
) (io.Reader, error) {
	// Unwrap through our own wrappers to find the underlying early conn.
	if !isEarlyConn(upstreamConn) {
		return clientReader, nil
	}

	// Set a short deadline for reading the first client data chunk.
	// The client should send data quickly (e.g. TLS ClientHello).
	_ = clientConn.SetReadDeadline(time.Now().Add(earlyHandshakeTimeout))

	buf := make([]byte, 16384) // 16KB — enough for TLS ClientHello
	n, readErr := clientReader.Read(buf)

	// Clear the read deadline regardless of outcome.
	_ = clientConn.SetReadDeadline(time.Time{})

	if n > 0 {
		// Write the first chunk to upstream — this triggers the protocol
		// handshake (Shadowsocks/VLESS header is prepended by the early conn).
		if _, writeErr := upstreamConn.Write(buf[:n]); writeErr != nil {
			return nil, writeErr
		}
	}

	if readErr != nil {
		// If we got a timeout but already wrote some data, that's OK —
		// the handshake has been triggered. But if we got no data at all,
		// propagate the error.
		if n == 0 {
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				// Client didn't send any data within the timeout.
				// Proceed with normal tunnel — the handshake will be
				// triggered by the first actual client write.
				return clientReader, nil
			}
			return nil, readErr
		}
		// Got data but also an error (e.g. EOF after the chunk).
		// The first chunk has been sent; return the error so the
		// tunnel copy sees it on the next read.
		if readErr == io.EOF {
			return &eofReader{}, nil
		}
	}

	return clientReader, nil
}

// isEarlyConn checks whether conn (possibly wrapped in our own layers)
// implements N.EarlyConn and needs a handshake.
func isEarlyConn(conn net.Conn) bool {
	// Unwrap our own wrapper layers to reach the underlying conn.
	current := conn
	for {
		if ec, ok := current.(N.EarlyConn); ok {
			return ec.NeedHandshake()
		}
		// Try to unwrap known wrapper types.
		switch w := current.(type) {
		case *tlsLatencyConn:
			current = w.Conn
		case *countingConn:
			current = w.Conn
		default:
			return false
		}
	}
}

// eofReader is a reader that always returns io.EOF.
type eofReader struct{}

func (r *eofReader) Read([]byte) (int, error) {
	return 0, io.EOF
}
