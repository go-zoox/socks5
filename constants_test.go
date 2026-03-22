package socks5

import "testing"

func TestConstants(t *testing.T) {
	if Version5 != 0x05 {
		t.Errorf("Version5 = %d, want 0x05", Version5)
	}
	if AuthNoAuthorizationRequired != 0x00 {
		t.Errorf("AuthNoAuthorizationRequired = %d, want 0x00", AuthNoAuthorizationRequired)
	}
	if AuthGSSAPI != 0x01 {
		t.Errorf("AuthGSSAPI = %d, want 0x01", AuthGSSAPI)
	}
	if AuthUserAndPassword != 0x02 {
		t.Errorf("AuthUserAndPassword = %d, want 0x02", AuthUserAndPassword)
	}
	if CmdConnect != 0x01 {
		t.Errorf("CmdConnect = %d, want 0x01", CmdConnect)
	}
	if CmdBind != 0x02 {
		t.Errorf("CmdBind = %d, want 0x02", CmdBind)
	}
	if CmdUDP != 0x03 {
		t.Errorf("CmdUDP = %d, want 0x03", CmdUDP)
	}
	if AddrTypeIPv4 != 0x01 {
		t.Errorf("AddrTypeIPv4 = %d, want 0x01", AddrTypeIPv4)
	}
	if AddrTypeFQDN != 0x03 {
		t.Errorf("AddrTypeFQDN = %d, want 0x03", AddrTypeFQDN)
	}
	if AddrTypeIPv6 != 0x04 {
		t.Errorf("AddrTypeIPv6 = %d, want 0x04", AddrTypeIPv6)
	}
}
