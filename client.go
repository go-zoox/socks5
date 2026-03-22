package socks5

import (
	"fmt"
	"io"
	"net"
)

type Client struct {
	conn net.Conn

	Host string `json:"host"`
	Port int    `json:"port"`
}

func (c *Client) authenticate() error {
	// Request
	b := []byte{Version5}
	availableAuthMethods := []byte{AuthNoAuthorizationRequired, AuthGSSAPI}
	b = append(b, byte(len(availableAuthMethods)))
	b = append(b, availableAuthMethods...)

	_, err := c.conn.Write(b)
	if err != nil {
		return err
	}

	buf := make([]byte, 256)
	// Response
	n, err := io.ReadFull(c.conn, buf[:2])
	if n != 2 {
		return fmt.Errorf("reading header: %s", err)
	}

	ver, method := int(buf[0]), int(buf[1])
	if ver != Version5 {
		return fmt.Errorf("unsupported SOCKS version %d", ver)
	}

	switch method {
	// 无需认证
	case AuthNoAuthorizationRequired:
		return nil
		// 用户名密码
	// case AuthUserAndPassword:
	// 	// @TO_IMPLEMENT
	default:
		return fmt.Errorf("unsupported method %d, only support no authentication currently", method)
	}
}

func (c *Client) connect(host string, port int) error {
	b := []byte{Version5, CmdConnect, 0x00, AddrTypeFQDN}
	b = append(b, byte(len(host)))
	b = append(b, host...)
	b = append(b, byte(port>>8), byte(port))

	// Request
	_, err := c.conn.Write(b)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d(error: %v)", host, port, err)
	}

	// Response: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
	header := make([]byte, 4)
	n, err := io.ReadFull(c.conn, header)
	if n != 4 {
		return fmt.Errorf("failed to read header: %v", err)
	}

	ver, rep, _, atyp := header[0], header[1], header[2], header[3]
	if ver != Version5 {
		return fmt.Errorf("unexpected SOCKS version in reply: %d", ver)
	}
	if rep != 0x00 {
		return fmt.Errorf("failed to connect to %s:%d (rep=%d)", host, port, rep)
	}

	// consume BND.ADDR according to ATYP and then BND.PORT so that no leftover bytes
	// from the CONNECT response will pollute subsequent application data.
	switch atyp {
	case AddrTypeIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c.conn, addr); err != nil {
			return fmt.Errorf("failed to read IPv4 bind address: %v", err)
		}
	case AddrTypeFQDN:
		// first length byte, then host bytes
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c.conn, lenBuf); err != nil {
			return fmt.Errorf("failed to read domain length: %v", err)
		}
		l := int(lenBuf[0])
		if l > 0 {
			hostBuf := make([]byte, l)
			if _, err := io.ReadFull(c.conn, hostBuf); err != nil {
				return fmt.Errorf("failed to read domain: %v", err)
			}
		}
	case AddrTypeIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(c.conn, addr); err != nil {
			return fmt.Errorf("failed to read IPv6 bind address: %v", err)
		}
	default:
		return fmt.Errorf("unsupported ATYP in reply: %d", atyp)
	}

	// read BND.PORT (2 bytes)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, portBuf); err != nil {
		return fmt.Errorf("failed to read bind port: %v", err)
	}

	return nil
}

func (c *Client) Connect(host string, port int, data []byte) ([]byte, error) {
	if c.conn == nil {
		conn, err := net.Dial("tcp", net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port)))
		if err != nil {
			return nil, err
		}

		c.conn = conn
	}

	// 1. authentication
	if err := c.authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %v", err)
	}

	// 2. connect
	if err := c.connect(host, port); err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}

	if _, err := c.conn.Write(data); err != nil {
		_ = c.conn.Close()
		c.conn = nil
		return nil, fmt.Errorf("failed to write: %v", err)
	}

	// read all response until EOF; this matches the CLI usage where the
	// server/remote closes the connection when done.
	var resp []byte
	buf := make([]byte, 4096)
	for {
		n, err := c.conn.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			// close and reset connection on any read error/EOF to avoid reusing bad state
			_ = c.conn.Close()
			c.conn = nil
			return resp, err
		}
	}
}
