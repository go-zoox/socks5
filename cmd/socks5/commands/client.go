package commands

import (
	"io"
	"os"

	"github.com/go-zoox/cli"
	"github.com/go-zoox/socks5"
)

func RegistryClient(app *cli.MultipleProgram) {
	app.Register("client", &cli.Command{
		Name:  "client",
		Usage: "socks5 client",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "server-host",
				Usage:   "server host",
				Aliases: []string{"SERVER_HOST"},
				Value:   "127.0.0.1",
			},
			&cli.IntFlag{
				Name:    "server-port",
				Usage:   "server port",
				Aliases: []string{"SERVER_PORT"},
				Value:   1080,
			},
			&cli.StringFlag{
				Name:     "host",
				Usage:    "request host",
				Aliases:  []string{"REQUEST_HOST"},
				Required: true,
			},
			&cli.IntFlag{
				Name:     "port",
				Usage:    "request port",
				Aliases:  []string{"REQUEST_PORT"},
				Required: true,
			},
		},
		Action: func(ctx *cli.Context) (err error) {
			client := socks5.Client{
				Host: ctx.String("server-host"),
				Port: ctx.Int("server-port"),
			}

			bytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}

			response, err := client.Connect(ctx.String("host"), ctx.Int("port"), bytes)
			if err != nil {
				return err
			}

			os.Stdout.Write(response)
			return
		},
	})
}

// echo "GET /ip HTTP/1.1\nHost: httpbin.org\nAccept: */*\nConnection: close\n\n\n" | go run ./cmd/socks5/main.go client --host httpbin.org --port 80
