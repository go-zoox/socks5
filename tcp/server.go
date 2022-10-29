package tcp

import (
	"net"

	"github.com/go-zoox/logger"
)

type Server struct {
}

func (s *Server) Run(addr string, onConnect func(client net.Conn)) error {
	server, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	for {
		client, err := server.Accept()
		if err != nil {
			logger.Warnf("accept failed: %v", err)
			continue
		}

		// request, _ := io.ReadAll(client)
		// fmt.Println(string(request))

		go onConnect(client)
	}
}
