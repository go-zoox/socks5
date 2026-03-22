package socks5

import (
	"io"
	"net"
	"testing"
)

// mockServerConnectOnly reads CONNECT request and sends CONNECT response (no auth). Use when testing connect() only.
func mockServerConnectOnly(conn net.Conn, connectRep byte, atyp byte) {
	buf := make([]byte, 256)
	_, _ = io.ReadFull(conn, buf[:4])
	atypReq := buf[3]
	var addrLen int
	switch atypReq {
	case 0x01:
		addrLen = 4
	case 0x03:
		_, _ = io.ReadFull(conn, buf[:1])
		addrLen = int(buf[0])
	case 0x04:
		addrLen = 16
	}
	_, _ = io.ReadFull(conn, buf[:addrLen])
	_, _ = io.ReadFull(conn, buf[:2])

	_, _ = conn.Write([]byte{0x05, connectRep, 0x00, atyp})
	switch atyp {
	case 0x01:
		_, _ = conn.Write([]byte{0, 0, 0, 0})
	case 0x03:
		_, _ = conn.Write([]byte{0})
	case 0x04:
		_, _ = conn.Write(make([]byte, 16))
	}
	_, _ = conn.Write([]byte{0x00, 0x00})
}

// mockServerConn runs full SOCKS5 (auth + connect response) and echoes application data.
func mockServerConn(t *testing.T, conn net.Conn, connectRep byte, atyp byte) {
	buf := make([]byte, 256)
	_, _ = io.ReadFull(conn, buf[:2])
	nMethods := int(buf[1])
	_, _ = io.ReadFull(conn, buf[:nMethods])
	_, _ = conn.Write([]byte{0x05, 0x00})

	_, _ = io.ReadFull(conn, buf[:4])
	atypReq := buf[3]
	var addrLen int
	switch atypReq {
	case 0x01:
		addrLen = 4
	case 0x03:
		_, _ = io.ReadFull(conn, buf[:1])
		addrLen = int(buf[0])
	case 0x04:
		addrLen = 16
	}
	_, _ = io.ReadFull(conn, buf[:addrLen])
	_, _ = io.ReadFull(conn, buf[:2])

	_, _ = conn.Write([]byte{0x05, connectRep, 0x00, atyp})
	switch atyp {
	case 0x01:
		_, _ = conn.Write([]byte{0, 0, 0, 0})
	case 0x03:
		_, _ = conn.Write([]byte{0})
	case 0x04:
		_, _ = conn.Write(make([]byte, 16))
	}
	_, _ = conn.Write([]byte{0x00, 0x00})

	if connectRep == 0x00 {
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write(buf[:n])
		}
		_ = conn.Close()
	}
}

func TestClient_authenticate_success(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 256)
		io.ReadFull(serverConn, buf[:2])
		nMethods := int(buf[1])
		io.ReadFull(serverConn, buf[:nMethods])
		serverConn.Write([]byte{0x05, 0x00})
	}()

	c := &Client{conn: clientConn, Host: "x", Port: 1}
	err := c.authenticate()
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
}

func TestClient_authenticate_wrong_version(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 256)
		io.ReadFull(serverConn, buf[:2])
		nMethods := int(buf[1])
		io.ReadFull(serverConn, buf[:nMethods])
		serverConn.Write([]byte{0x04, 0x00}) // wrong VER
	}()

	c := &Client{conn: clientConn}
	err := c.authenticate()
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestClient_authenticate_unsupported_method(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 256)
		io.ReadFull(serverConn, buf[:2])
		nMethods := int(buf[1])
		io.ReadFull(serverConn, buf[:nMethods])
		serverConn.Write([]byte{0x05, 0x02}) // USERNAME/PASSWORD not implemented
	}()

	c := &Client{conn: clientConn}
	err := c.authenticate()
	if err == nil {
		t.Fatal("expected error for unsupported method")
	}
}

func TestClient_connect_success_IPv4_response(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		mockServerConnectOnly(serverConn, 0x00, AddrTypeIPv4)
	}()

	c := &Client{conn: clientConn}
	err := c.connect("example.com", 80)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
}

func TestClient_connect_success_FQDN_response(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		mockServerConnectOnly(serverConn, 0x00, AddrTypeFQDN)
	}()

	c := &Client{conn: clientConn}
	err := c.connect("example.com", 443)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
}

func TestClient_connect_success_IPv6_response(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		mockServerConnectOnly(serverConn, 0x00, AddrTypeIPv6)
	}()

	c := &Client{conn: clientConn}
	err := c.connect("example.com", 80)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
}

func TestClient_connect_rep_failure(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		mockServerConnectOnly(serverConn, 0x01, AddrTypeIPv4) // rep=1 (general failure)
	}()

	c := &Client{conn: clientConn}
	err := c.connect("example.com", 80)
	if err == nil {
		t.Fatal("expected error when rep != 0")
	}
}

func TestClient_Connect_full_flow_no_leftover_bytes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		mockServerConn(t, conn, 0x00, AddrTypeIPv4)
	}()

	addr := listener.Addr().String()
	host, _, _ := net.SplitHostPort(addr)
	var port int
	if a, ok := listener.Addr().(*net.TCPAddr); ok {
		port = a.Port
	}

	c := &Client{Host: host, Port: port}
	data := []byte("hello")
	out, err := c.Connect(host, port, data)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	// Echo server sends back what we sent. Response must not contain SOCKS header bytes.
	if len(out) < len(data) {
		t.Fatalf("short response: %d", len(out))
	}
	if string(out[:5]) != "hello" {
		t.Errorf("expected hello, got %q (first bytes might be leftover SOCKS response)", out[:5])
	}
}

func TestClient_Connect_conn_nil_after_EOF(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn == nil {
			return
		}
		mockServerConn(t, conn, 0x00, AddrTypeIPv4)
	}()

	addr := listener.Addr().String()
	host, _, _ := net.SplitHostPort(addr)
	var port int
	if a, ok := listener.Addr().(*net.TCPAddr); ok {
		port = a.Port
	}

	c := &Client{Host: host, Port: port}
	_, _ = c.Connect(host, port, []byte("x"))
	if c.conn != nil {
		t.Error("expected conn to be nil after EOF")
	}
}

func TestClient_Connect_dial_failure(t *testing.T) {
	c := &Client{Host: "127.0.0.1", Port: 1}
	_, err := c.Connect("example.com", 80, []byte("x"))
	if err != nil {
		// may fail on dial or later; either way we expect an error when port 1 is not listening
		return
	}
	t.Fatal("expected error when dialing closed port")
}

