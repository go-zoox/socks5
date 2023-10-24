package commands

import (
	"fmt"
	"net"

	"github.com/go-zoox/cli"
	"github.com/go-zoox/logger"
	"github.com/go-zoox/socks5"
)

func RegistryServer(app *cli.MultipleProgram) {
	app.Register("server", &cli.Command{
		Name:  "server",
		Usage: "socks5 server",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "port",
				Usage:   "server port",
				Aliases: []string{"p"},
				EnvVars: []string{"PORT"},
				Value:   1080,
			},
		},
		Action: func(ctx *cli.Context) (err error) {
			s := &socks5.Server{
				OnConnect: func(conn net.Conn, source string, target string) {
					logger.Info("[%s] connect to %s", source, target)
				},
			}

			logger.Infof("start socks5 server at: %s ...", "0.0.0.0:1080")

			return s.Run(fmt.Sprintf(":%d", ctx.Int("port")))
		},
	})
}
