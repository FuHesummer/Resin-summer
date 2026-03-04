package proxy

import (
	"bufio"
	"net"
)

// ProtocolMuxListener wraps a net.Listener and dispatches accepted connections
// to either a SOCKS5 handler or the HTTP server based on the first byte.
//
// SOCKS5 connections start with 0x05 (protocol version).
// Everything else is treated as HTTP.
type ProtocolMuxListener struct {
	base    net.Listener
	socks5  *Socks5Server
	httpCh  chan net.Conn // accepted HTTP connections forwarded here
	closeCh chan struct{}
}

// NewProtocolMuxListener creates a listener that auto-detects SOCKS5 vs HTTP
// on the same TCP port. HTTP connections are returned by Accept(); SOCKS5
// connections are dispatched directly to the socks5 server.
func NewProtocolMuxListener(base net.Listener, socks5 *Socks5Server) *ProtocolMuxListener {
	ml := &ProtocolMuxListener{
		base:    base,
		socks5:  socks5,
		httpCh:  make(chan net.Conn, 64),
		closeCh: make(chan struct{}),
	}
	go ml.acceptLoop()
	return ml
}

func (ml *ProtocolMuxListener) acceptLoop() {
	for {
		conn, err := ml.base.Accept()
		if err != nil {
			close(ml.httpCh) // signal Accept() callers
			return
		}
		go ml.dispatch(conn)
	}
}

func (ml *ProtocolMuxListener) dispatch(conn net.Conn) {
	// Peek the first byte to determine protocol.
	br := bufio.NewReaderSize(conn, 1)
	first, err := br.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	peekedConn := &peekedConn{Conn: conn, reader: br}

	if first[0] == socks5Version { // 0x05
		// SOCKS5 — handle directly; close when done.
		defer peekedConn.Close()
		ml.socks5.HandleConn(peekedConn) // context handled internally
		return
	}

	// HTTP — send to the channel for http.Server.Serve() to pick up.
	select {
	case ml.httpCh <- peekedConn:
	case <-ml.closeCh:
		conn.Close()
	}
}

// Accept returns the next HTTP connection. Blocks until one is available.
// Implements net.Listener.
func (ml *ProtocolMuxListener) Accept() (net.Conn, error) {
	conn, ok := <-ml.httpCh
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

// Close closes the underlying listener and stops the accept loop.
func (ml *ProtocolMuxListener) Close() error {
	select {
	case <-ml.closeCh:
	default:
		close(ml.closeCh)
	}
	return ml.base.Close()
}

// Addr returns the listener's network address.
func (ml *ProtocolMuxListener) Addr() net.Addr {
	return ml.base.Addr()
}

// peekedConn wraps a net.Conn with a bufio.Reader that has already peeked
// the first byte. Read() drains the buffered byte first.
type peekedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *peekedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}
