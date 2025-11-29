package components

import (
	"testing"
)

func TestIsIPv6Address(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    bool
	}{
		{"valid ipv6", "2001:db8::1", true},
		{"valid ipv6 full", "2001:0db8:0000:0000:0000:0000:0000:0001", true},
		{"valid ipv6 loopback", "::1", true},
		{"valid ipv6 all zeros", "::", true},
		{"ipv4", "192.168.1.1", false},
		{"ipv4 localhost", "127.0.0.1", false},
		{"empty", "", false},
		{"invalid", "invalid", false},
		{"ipv4 mapped ipv6", "::ffff:192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIPv6Address(tt.address)
			if got != tt.want {
				t.Errorf("IsIPv6Address(%s) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}

func TestIsIPv6CIDR(t *testing.T) {
	tests := []struct {
		name string
		cidr string
		want bool
	}{
		{"valid ipv6 /64", "2001:db8::/64", true},
		{"valid ipv6 /128", "2001:db8::1/128", true},
		{"valid ipv6 /0", "::/0", true},
		{"valid ipv6 private", "fc00::/7", true},
		{"ipv4 cidr", "192.168.1.0/24", false},
		{"ipv4 all", "0.0.0.0/0", false},
		{"empty", "", false},
		{"invalid", "invalid", false},
		{"no prefix", "2001:db8::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIPv6CIDR(tt.cidr)
			if got != tt.want {
				t.Errorf("IsIPv6CIDR(%s) = %v, want %v", tt.cidr, got, tt.want)
			}
		})
	}
}

func TestNormalizeIPv6Address(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
	}{
		{"already normalized", "2001:db8::1", "2001:db8::1"},
		{"full to compressed", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"loopback", "0000:0000:0000:0000:0000:0000:0000:0001", "::1"},
		{"ipv4 unchanged", "192.168.1.1", "192.168.1.1"},
		{"invalid unchanged", "invalid", "invalid"},
		{"empty unchanged", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeIPv6Address(tt.address)
			if got != tt.want {
				t.Errorf("NormalizeIPv6Address(%s) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}

func TestIPv6MatchesCIDR(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		cidr string
		want bool
	}{
		{"match /64", "2001:db8::1", "2001:db8::/64", true},
		{"match /128", "2001:db8::1", "2001:db8::1/128", true},
		{"no match /64", "2001:db8:1::1", "2001:db8::/64", false},
		{"match all", "2001:db8::1", "::/0", true},
		{"ipv4 in ipv6 cidr", "192.168.1.1", "2001:db8::/64", false},
		{"ipv6 in ipv4 cidr", "2001:db8::1", "192.168.1.0/24", false},
		{"invalid ip", "invalid", "2001:db8::/64", false},
		{"invalid cidr", "2001:db8::1", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IPv6MatchesCIDR(tt.ip, tt.cidr)
			if got != tt.want {
				t.Errorf("IPv6MatchesCIDR(%s, %s) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
			}
		})
	}
}

func TestIsIPv6Protocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		want     bool
	}{
		{"icmpv6", "icmpv6", true},
		{"icmpv6 upper", "ICMPV6", true},
		{"protocol 58", "58", true},
		{"icmp", "icmp", false},
		{"tcp", "tcp", false},
		{"udp", "udp", false},
		{"protocol 1", "1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIPv6Protocol(tt.protocol)
			if got != tt.want {
				t.Errorf("IsIPv6Protocol(%s) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}

func TestGetIPVersion(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
	}{
		{"ipv4", "192.168.1.1", "ipv4"},
		{"ipv4 localhost", "127.0.0.1", "ipv4"},
		{"ipv6", "2001:db8::1", "ipv6"},
		{"ipv6 loopback", "::1", "ipv6"},
		{"invalid", "invalid", "unknown"},
		{"empty", "", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetIPVersion(tt.address)
			if got != tt.want {
				t.Errorf("GetIPVersion(%s) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}
