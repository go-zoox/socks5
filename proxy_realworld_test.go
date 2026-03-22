package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestRealWorld_HTTPProxyThroughSocks5(t *testing.T) {
	// target HTTP server
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ping" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("pong"))
	}))
	defer target.Close()

	targetURL := target.URL + "/ping"
	targetHost, targetPort := mustSplitHostPortURL(t, target.URL)

	// socks5 server: test-controlled accept loop (avoid tcp.Server.Run infinite loop)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}
	defer ln.Close()

	s := &Server{
		Auth: Auth{Method: "none"},
	}

	stop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
					return
				}
			}
			go s.process(conn)
		}
	}()
	defer close(stop)

	// http client that dials the target via socks5
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// addr is the target host:port as requested by http.Transport
			h, pStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			p, err := strconv.Atoi(pStr)
			if err != nil {
				return nil, err
			}

			socksConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
			if err != nil {
				return nil, err
			}

			c := &Client{conn: socksConn}
			if err := c.authenticate(); err != nil {
				_ = socksConn.Close()
				return nil, fmt.Errorf("socks authenticate: %w", err)
			}
			if err := c.connect(h, p); err != nil {
				_ = socksConn.Close()
				return nil, fmt.Errorf("socks connect: %w", err)
			}

			return socksConn, nil
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	// request to target URL; dialer will route through socks5
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET via socks5: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status: %d, body=%q", resp.StatusCode, string(b))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(b) != "pong" {
		t.Fatalf("unexpected body: %q", string(b))
	}

	// sanity check: ensure our target server is actually the one being hit
	if targetHost == "" || targetPort == 0 {
		t.Fatalf("bad target host/port: %q %d", targetHost, targetPort)
	}
}

func mustSplitHostPortURL(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := http.NewRequest("GET", raw, nil)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	host := u.URL.Hostname()
	portStr := u.URL.Port()
	if portStr == "" {
		t.Fatalf("missing port in url: %s", raw)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, port
}

