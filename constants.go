package socks5

const (
	Version5 = 0x05

	AuthNoAuthorizationRequired = 0x00
	AuthGSSAPI                  = 0x01
	AuthUserAndPassword         = 0x02

	CmdConnect = 0x01
	CmdBind    = 0x02
	CmdUDP     = 0x03

	AddrTypeIPv4 = 0x01
	AddrTypeFQDN = 0x03
	AddrTypeIPv6 = 0x04
)
