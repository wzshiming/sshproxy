package sshproxy

import (
	"net"
	"sync"
	"sync/atomic"
)

func connWithCloser(conn net.Conn, closer func() error) net.Conn {
	return &connCloser{Conn: conn, closer: closer}
}

type connCloser struct {
	net.Conn
	closer func() error
}

func (w *connCloser) Close() error {
	return w.closer()
}

func connWithAddr(conn net.Conn, localAddr, remoteAddr net.Addr) net.Conn {
	return &connAddr{Conn: conn, localAddr: localAddr, remoteAddr: remoteAddr}
}

type connAddr struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (w *connAddr) LocalAddr() net.Addr {
	if w.localAddr == nil {
		return w.Conn.LocalAddr()
	}
	return w.localAddr
}

func (w *connAddr) RemoteAddr() net.Addr {
	if w.remoteAddr == nil {
		return w.Conn.RemoteAddr()
	}
	return w.remoteAddr
}

func newConnRecord(conn net.Conn) *connRecord {
	return &connRecord{Conn: conn, end: make(chan struct{})}
}

// connRecord counts the bytes read from a connection and notes its end.
type connRecord struct {
	net.Conn
	read    atomic.Int64
	end     chan struct{}
	endOnce sync.Once
	onEnd   func() // optional, runs once as the connection ends
}

func (w *connRecord) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	w.read.Add(int64(n))
	if err != nil {
		w.markEnded()
	}
	return n, err
}

func (w *connRecord) Write(b []byte) (int, error) {
	n, err := w.Conn.Write(b)
	if err != nil {
		w.markEnded()
	}
	return n, err
}

func (w *connRecord) Close() error {
	err := w.Conn.Close()
	w.markEnded()
	return err
}

func (w *connRecord) markEnded() {
	w.endOnce.Do(func() {
		if w.onEnd != nil {
			w.onEnd()
		}
		close(w.end)
	})
}

func (w *connRecord) ended() bool {
	select {
	case <-w.end:
		return true
	default:
		return false
	}
}

func (w *connRecord) done() <-chan struct{} {
	return w.end
}

func (w *connRecord) arrived() int64 {
	return w.read.Load()
}

func newNetAddr(network, address string) net.Addr {
	return &addr{network: network, address: address}
}

type addr struct {
	network string
	address string
}

func (a *addr) Network() string {
	return a.network
}
func (a *addr) String() string {
	return a.address
}
