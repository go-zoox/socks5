package socks5

// referneces:
//   https://segmentfault.com/a/1190000038247560
//   https://www.rfc-editor.org/rfc/rfc1928
//   https://blog.hsm.cool/index.php/archives/821/
//
//	 https://luyuhuang.tech/2020/12/02/subsocks.html
//   https://juejin.cn/post/7099009430481534989
//   https://juejin.cn/post/7037351835748794382

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/go-zoox/logger"
	"github.com/go-zoox/socks5/tcp"
)

type Server struct {
	tcp.Server

	Auth Auth `json:"auth"`

	OnConnect func(conn net.Conn, source, target string)
}

type Auth struct {
	// none 				- no authentication
	// credentials 	- no authentication
	Method string `json:"method"`

	// when method is credentials
	Username string `json:"username"`
	Password string `json:"password"`

	// // when method is token
	// Token string `json:"token"`
}

func (s *Server) Run(addr string) error {
	tcpServer := tcp.Server{}

	return tcpServer.Run(addr, func(client net.Conn) {
		s.process(client)
	})
}

func (s *Server) process(client net.Conn) {
	// 1. 认证
	if err := s.authenticate(client); err != nil {
		logger.Errorf("auth error: %v", err)
		client.Close()
		return
	}

	// 2. 建立连接
	target, err := s.connect(client)
	if err != nil {
		logger.Errorf("connect error: %v", err)
		client.Close()
		return
	}

	// 3. 转发数据
	s.forward(client, target)
}

// Auth Request Protocol:
// 	VER | NMETHODS | METHODS
// 	1   | 1        | 1
//
// 	VER - 本次请求的协议版本号，取固定值 0x05（表示socks 5）
//  NMETHODS - 客户端支持的认证方式数量，可取值 1~255
//  METHODS - 可用的认证方式列表
//
//		0x00 NO AUTHENTICATION REQUIRED 无需认证
// 		0x01 GSSAPI
// 		0x02 USERNAME/PASSWORD 无需认证
// 		0x03 to 0x7F IANA ASSIGNED
// 		0x80 to 0xFE REVERSED FOR PRIVATE METHODS
// 		0xFF NO ACCEPTABLE METHODS
//
//
// Auth Response Protocol:
//   VER | METHOD
//   1   |   1
//
//   VER 		- 协议版本
//   METHOD - 服务端期望的认证方式
//
func (s *Server) authenticate(client net.Conn) error {
	buf := make([]byte, 256)

	// 读取 VER 和 NMETHODS
	n, err := io.ReadFull(client, buf[:2])
	if n != 2 {
		return fmt.Errorf("reading header: %s", err)
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	// 读取客户端支持的 METHODS 列表
	n, err = io.ReadFull(client, buf[:nMethods])
	if n != nMethods {
		return fmt.Errorf("reading methods: %s", err)
	}

	// @TODO 这里写死认证方式：无需认证
	_, err = client.Write([]byte{0x05, 0x00})
	if err != nil {
		return fmt.Errorf("writing methods: %s", err)
	}

	return nil
}

// Connect Request Protocol:
//   VER | CMD | RSV  | ATYP | DST.ADDR | DST.PORT
//    1  |  1  | 0x00 |  1   | Variable | 2
//
//   VER - 本次请求的协议版本号，取固定值 0x05（表示socks 5）
//   CMD - 连接方式，0x01:CONNECT, 0x02:BIND, 0x03:UDP ASSOCAITE
//   RSV - 保留字段，没用
//   ATYP - 地址类型，0x01:IPv4, 0x03:域名, 0x04:IPv6
//   DST.ADDR - 目标地址
//   DST.PORT - 目标端口，2字节，网络字节序（network octec order）
//
//
// 	Connect Response Protocl:
//  	VER | REP | RSV  | ATYP | BND.ADDR | BND.PORT
//    1   |  1  | 0x00 |  1   | Variable | 2
//
//    VER  - 本次请求的协议版本号，取固定值 0x05（表示socks 5）
//    REP  - 状态码，0x00:成功，0x01:失败
//    RSV  - 保留字段，没用
//    ATYP - 地址类型，0x01:IPv4, 0x03:域名, 0x04:IPv6
//    BND.ADDR - 服务器和 DST 创建连接的地址，基本上没用，默认用: 0
//    BND.PORT - 服务器和 DST 创建连接的端口，基本上没用，默认用：0
//
func (s *Server) connect(client net.Conn) (net.Conn, error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(client, buf[:4])
	if n != 4 {
		return nil, fmt.Errorf("read headers: %s", err)
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 {
		return nil, fmt.Errorf("invald ver: %d", ver)
	}

	switch cmd {
	case 0x01:
		// CONNECT
	default:
		// FALLBACK
		return nil, fmt.Errorf("invald cmd: %d", cmd)
	}

	addr := ""
	switch atyp {
	// IPv4
	case 1:
		n, err = io.ReadFull(client, buf[:4])
		if n != 4 {
			return nil, fmt.Errorf("invalid IPv4: %s", err)
		}

		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])

	// DOMAINNAME
	case 3:
		n, err = io.ReadFull(client, buf[:1])
		if n != 1 {
			return nil, fmt.Errorf("invalid hostname(1): %s", err)
		}
		addrLen := int(buf[0])

		n, err = io.ReadFull(client, buf[:addrLen])
		if n != addrLen {
			return nil, fmt.Errorf("invalid hostname(2): %s", err)
		}

		addr = string(buf[:addrLen])

	// IPv6
	case 4:
		return nil, errors.New("IPv6: not supported yet")

	default:
		return nil, fmt.Errorf("invalid atyp: %d", atyp)
	}

	n, err = io.ReadFull(client, buf[:2])
	if n != 2 {
		return nil, fmt.Errorf("read port: %s", err)
	}
	port := binary.BigEndian.Uint16(buf[:2])

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	// logger.Info("[%s] connect to %s", client.RemoteAddr().String(), destAddrPort)
	if s.OnConnect != nil {
		s.OnConnect(client, client.RemoteAddr().String(), destAddrPort)
	}

	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return nil, fmt.Errorf("dial dst: %s", err)
	}

	_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		dest.Close()
		return nil, fmt.Errorf("write response: %s", err)
	}

	return dest, nil
}

func (s *Server) forward(client net.Conn, target net.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()

		io.Copy(src, dest)

		cancel()
	}

	go forward(client, target)
	go forward(target, client)

	<-ctx.Done()
}
