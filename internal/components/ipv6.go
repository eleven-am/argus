package components

import (
	"net"
	"strings"
)

// IsIPv6Address returns true if the given address is a valid IPv6 address.
func IsIPv6Address(address string) bool {
	if address == "" {
		return false
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// IsIPv6CIDR returns true if the given CIDR is a valid IPv6 CIDR.
func IsIPv6CIDR(cidr string) bool {
	if cidr == "" {
		return false
	}
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ip.To4() == nil
}

// NormalizeIPv6Address normalizes an IPv6 address to its canonical form.
func NormalizeIPv6Address(address string) string {
	ip := net.ParseIP(address)
	if ip == nil {
		return address
	}
	if ip.To4() != nil {
		return address
	}
	return ip.String()
}

// IPv6MatchesCIDR checks if an IPv6 address matches a CIDR.
// This is a convenience wrapper around IPMatchesCIDR for explicit IPv6 operations.
func IPv6MatchesCIDR(ip, cidr string) bool {
	if !IsIPv6Address(ip) || !IsIPv6CIDR(cidr) {
		return false
	}
	return IPMatchesCIDR(ip, cidr)
}

// IsIPv6Protocol returns true if the protocol is IPv6-specific.
func IsIPv6Protocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "icmpv6", "58":
		return true
	}
	return false
}

// GetIPVersion returns "ipv4", "ipv6", or "unknown" for the given address.
func GetIPVersion(address string) string {
	ip := net.ParseIP(address)
	if ip == nil {
		return "unknown"
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}
