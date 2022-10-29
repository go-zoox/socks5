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

	// Response
	buf := make([]byte, 256)
	n, err := io.ReadFull(c.conn, buf[:2])
	if n != 2 {
		return fmt.Errorf("failed to read header: %s", err)
	}
	rep := buf[1]
	if rep != 0x00 {
		return fmt.Errorf("failed to connect to %s:%d(rep: %d)", host, port, rep)
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
		return nil, fmt.Errorf("failed to write: %v", err)
	}

	// response, err := io.ReadAll(c.conn)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to read response: %v", err)
	// }

	b := make([]byte, 0, 512)
	for {
		if len(b) == cap(b) {
			b = append(b, 0)[:len(b)]
		}

		n, err := c.conn.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}

			return b, err
		}

		// fmt.Println("n:", n)

		// // @TODO
		// if n != 8 && n != 512 {
		// 	return b, nil
		// }
	}
}
