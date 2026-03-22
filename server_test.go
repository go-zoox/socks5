package socks5

import (
	"io"
	"net"
	"testing"
)

func TestServer_authenticate_none_success(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Pipe blocks: server Write blocks until client Read. So read response in goroutine.
	respCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		b := make([]byte, 2)
		_, e := io.ReadFull(clientConn, b)
		if e != nil {
			errCh <- e
			return
		}
		respCh <- b
	}()
	go func() { _, _ = clientConn.Write([]byte{0x05, 0x01, 0x00}) }()

	s := &Server{}
	err := s.authenticate(serverConn)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	buf := <-respCh
	if len(buf) != 2 {
		t.Fatalf("read response: %v", <-errCh)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		t.Errorf("expected VER=0x05 METHOD=0x00, got %02x %02x", buf[0], buf[1])
	}
}

func TestServer_authenticate_invalid_version(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() { _, _ = clientConn.Write([]byte{0x04, 0x01, 0x00}) }() // wrong version

	s := &Server{}
	err := s.authenticate(serverConn)
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
}

func TestServer_authenticate_unsupported_method(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	respCh := make(chan []byte, 1)
	go func() {
		b := make([]byte, 2)
		_, _ = io.ReadFull(clientConn, b)
		respCh <- b
	}()
	go func() { _, _ = clientConn.Write([]byte{0x05, 0x01, 0x00}) }()

	s := &Server{Auth: Auth{Method: "credentials"}}
	err := s.authenticate(serverConn)
	if err == nil {
		t.Fatal("expected error for credentials (not implemented)")
	}

	buf := <-respCh
	if buf[0] != 0x05 || buf[1] != 0xFF {
		t.Errorf("expected NO ACCEPTABLE METHODS (0xFF), got %02x %02x", buf[0], buf[1])
	}
}

func TestServer_authenticate_client_does_not_support_none(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	respCh := make(chan []byte, 1)
	go func() {
		b := make([]byte, 2)
		_, _ = io.ReadFull(clientConn, b)
		respCh <- b
	}()
	go func() { _, _ = clientConn.Write([]byte{0x05, 0x01, 0x01}) }()

	s := &Server{} // default method is "none"
	err := s.authenticate(serverConn)
	if err == nil {
		t.Fatal("expected error when client does not support none")
	}

	buf := <-respCh
	if buf[1] != 0xFF {
		t.Errorf("expected 0xFF, got %02x", buf[1])
	}
}

func TestServer_connect_IPv4_success(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// CONNECT 127.0.0.1:12345
	req := []byte{
		0x05, 0x01, 0x00, 0x01, // VER, CMD, RSV, ATYP=IPv4
		127, 0, 0, 1,           // 127.0.0.1
		0x30, 0x39,             // port 12345
	}
	targetConn, targetPeer := net.Pipe()
	defer targetConn.Close()
	defer targetPeer.Close()

	respCh := make(chan []byte, 1)
	go func() {
		b := make([]byte, 10)
		_, _ = io.ReadFull(clientConn, b)
		respCh <- b
	}()
	go func() { _, _ = clientConn.Write(req) }()

	s := &Server{
		OnConn: func(_ net.Conn, _, target string) (net.Conn, error) {
			return targetConn, nil
		},
	}
	gotTarget, err := s.connect(serverConn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer gotTarget.Close()
	if gotTarget != targetConn {
		t.Error("expected returned conn to be the OnConn result")
	}

	resp := <-respCh
	if resp[0] != 0x05 || resp[1] != 0x00 || resp[2] != 0x00 || resp[3] != 0x01 {
		t.Errorf("unexpected response header: %v", resp[:4])
	}
	_ = targetPeer
}

func TestServer_connect_domain_success(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// CONNECT example.com:80
	req := []byte{
		0x05, 0x01, 0x00, 0x03, // VER, CMD, RSV, ATYP=domain
		11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x00, 0x50, // port 80
	}
	targetConn, _ := net.Pipe()
	defer targetConn.Close()

	respCh := make(chan []byte, 1)
	go func() {
		b := make([]byte, 10)
		_, _ = io.ReadFull(clientConn, b)
		respCh <- b
	}()
	go func() { _, _ = clientConn.Write(req) }()

	s := &Server{
		OnConn: func(_ net.Conn, _, target string) (net.Conn, error) {
			if target != "example.com:80" {
				t.Errorf("expected target example.com:80, got %s", target)
			}
			return targetConn, nil
		},
	}
	_, err := s.connect(serverConn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	resp := <-respCh
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Errorf("unexpected response: %v", resp[:2])
	}
}

func TestServer_connect_IPv6_not_supported(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	req := []byte{
		0x05, 0x01, 0x00, 0x04, // ATYP=IPv6
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0x00, 0x50,
	}
	go func() { _, _ = clientConn.Write(req) }()

	s := &Server{}
	_, err := s.connect(serverConn)
	if err == nil {
		t.Fatal("expected error for IPv6")
	}
	if err.Error() != "IPv6: not supported yet" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestServer_connect_invalid_cmd(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	req := []byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50} // CMD=BIND
	go func() { _, _ = clientConn.Write(req) }()

	s := &Server{}
	_, err := s.connect(serverConn)
	if err == nil {
		t.Fatal("expected error for BIND")
	}
}

func TestServer_connect_invalid_ver(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	req := []byte{0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50}
	go func() { _, _ = clientConn.Write(req) }()

	s := &Server{}
	_, err := s.connect(serverConn)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestServer_connect_OnConn_returns_error(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50}
	go func() { _, _ = clientConn.Write(req) }()

	s := &Server{
		OnConn: func(_ net.Conn, _, _ string) (net.Conn, error) {
			return nil, io.EOF
		},
	}
	_, err := s.connect(serverConn)
	if err == nil {
		t.Fatal("expected error when OnConn returns error")
	}
}

func TestServer_connect_invalid_atyp(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	req := []byte{0x05, 0x01, 0x00, 0x99, 127, 0, 0, 1, 0x00, 0x50}
	go func() { _, _ = clientConn.Write(req) }()

	s := &Server{}
	_, err := s.connect(serverConn)
	if err == nil {
		t.Fatal("expected error for invalid atyp")
	}
}

func TestServer_forward(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	targetConn, targetPeer := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	defer targetConn.Close()
	defer targetPeer.Close()

	s := &Server{}
	go s.forward(serverConn, targetConn)

	// Client sends "hello" -> should be copied to targetPeer
	go func() {
		_, _ = clientConn.Write([]byte("hello"))
	}()

	buf := make([]byte, 5)
	_, err := io.ReadFull(targetPeer, buf)
	if err != nil {
		t.Fatalf("target read: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("target got %q", buf)
	}

	// Target sends "world" -> should be copied to client
	_, _ = targetPeer.Write([]byte("world"))
	resp := make([]byte, 5)
	_, err = io.ReadFull(clientConn, resp)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(resp) != "world" {
		t.Errorf("client got %q", resp)
	}

	_ = targetPeer.Close()
	_ = clientConn.Close()
}

func TestServer_process_auth_then_connect_then_forward(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// Echo server: accept one conn and echo back
	echoDone := make(chan struct{})
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			_, _ = conn.Write(buf[:n])
			_ = conn.Close()
		}
		close(echoDone)
	}()

	clientConn, serverConn := net.Pipe()

	s := &Server{
		OnConn: func(_ net.Conn, _, target string) (net.Conn, error) {
			return net.Dial("tcp", target)
		},
	}
	go s.process(serverConn)

	// 1. Auth
	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	_, _ = io.ReadFull(clientConn, buf)
	if buf[0] != 0x05 || buf[1] != 0x00 {
		t.Fatalf("auth response: %v", buf)
	}

	// 2. CONNECT to echo server (domain style: we need to send host and port)
	host := "127.0.0.1"
	var port uint16
	if a, ok := listener.Addr().(*net.TCPAddr); ok {
		port = uint16(a.Port)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	_, _ = clientConn.Write(req)

	resp := make([]byte, 10)
	_, _ = io.ReadFull(clientConn, resp)
	if resp[1] != 0x00 {
		t.Fatalf("connect failed rep=%d", resp[1])
	}

	// 3. Send "ping", expect "ping" back
	_, _ = clientConn.Write([]byte("ping"))
	out := make([]byte, 4)
	_, err = io.ReadFull(clientConn, out)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(out) != "ping" {
		t.Errorf("expected ping, got %q", out)
	}

	_ = clientConn.Close()
	<-echoDone
}

func TestServer_Run_invalid_addr_returns_error(t *testing.T) {
	s := &Server{}
	// Run with invalid address should return listen error (e.g. "invalid address" or "missing port").
	err := s.Run("invalid-address-no-port")
	if err == nil {
		t.Fatal("expected Run to return error for invalid address")
	}
}
