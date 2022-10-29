package main

import (
	"net"

	"github.com/go-zoox/logger"
	"github.com/go-zoox/socks5"
)

func main() {
	s := &socks5.Server{
		OnConnect: func(conn net.Conn, source string, target string) {
			logger.Info("[%s] connect to %s", source, target)
		},
	}
	logger.Infof("start socks5 server at: %s ...", "0.0.0.0:1080")
	if err := s.Run(":1080"); err != nil {
		logger.Fatal("failed to start socks5 server: %s", err)
	}
}
