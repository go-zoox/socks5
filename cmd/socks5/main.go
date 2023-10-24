package main

import (
	"github.com/go-zoox/cli"
	"github.com/go-zoox/socks5"
	"github.com/go-zoox/socks5/cmd/socks5/commands"
)

func main() {
	app := cli.NewMultipleProgram(&cli.MultipleProgramConfig{
		Name:    "socks5",
		Usage:   "socks5 server and client",
		Version: socks5.Version,
	})

	// server
	commands.RegistryServer(app)
	// client
	commands.RegistryClient(app)

	app.Run()
}
