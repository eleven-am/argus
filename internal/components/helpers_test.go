package components

import (
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestIPMatchesCIDR(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		cidr string
		want bool
	}{
		{"exact match", "10.0.0.1", "10.0.0.0/8", true},
		{"within /24", "192.168.1.50", "192.168.1.0/24", true},
		{"outside /24", "192.168.2.1", "192.168.1.0/24", false},
		{"all traffic", "8.8.8.8", "0.0.0.0/0", true},
		{"private in public", "10.0.0.1", "0.0.0.0/0", true},
		{"single host /32", "10.0.0.5", "10.0.0.5/32", true},
		{"not single host", "10.0.0.6", "10.0.0.5/32", false},
		{"invalid cidr", "10.0.0.1", "invalid", false},
		{"invalid ip", "invalid", "10.0.0.0/8", false},
		{"empty ip", "", "10.0.0.0/8", false},
		{"empty cidr", "10.0.0.1", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IPMatchesCIDR(tt.ip, tt.cidr)
			if got != tt.want {
				t.Errorf("IPMatchesCIDR(%s, %s) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
			}
		})
	}
}

func TestSortNACLRulesByNumber(t *testing.T) {
	rules := []domain.NACLRule{
		{RuleNumber: 200, Action: "allow"},
		{RuleNumber: 100, Action: "deny"},
		{RuleNumber: 32767, Action: "deny"},
		{RuleNumber: 150, Action: "allow"},
	}

	sorted := SortNACLRulesByNumber(rules)

	if sorted[0].RuleNumber != 100 {
		t.Errorf("expected first rule 100, got %d", sorted[0].RuleNumber)
	}
	if sorted[1].RuleNumber != 150 {
		t.Errorf("expected second rule 150, got %d", sorted[1].RuleNumber)
	}
	if sorted[2].RuleNumber != 200 {
		t.Errorf("expected third rule 200, got %d", sorted[2].RuleNumber)
	}
	if sorted[3].RuleNumber != 32767 {
		t.Errorf("expected fourth rule 32767, got %d", sorted[3].RuleNumber)
	}

	if rules[0].RuleNumber != 200 {
		t.Error("original slice was modified")
	}
}

func TestProtocolMatches(t *testing.T) {
	tests := []struct {
		name         string
		ruleProtocol string
		destProtocol string
		want         bool
	}{
		{"all protocols", "-1", "tcp", true},
		{"all protocols udp", "-1", "udp", true},
		{"tcp matches tcp", "tcp", "tcp", true},
		{"tcp not udp", "tcp", "udp", false},
		{"udp matches udp", "udp", "udp", true},
		{"icmp matches icmp", "icmp", "icmp", true},
		{"icmpv6 matches icmpv6", "icmpv6", "icmpv6", true},
		{"protocol 58 matches icmpv6", "58", "icmpv6", true},
		{"protocol 1 matches icmp", "1", "icmp", true},
		{"protocol 6 matches tcp", "6", "tcp", true},
		{"protocol 17 matches udp", "17", "udp", true},
		{"icmp not icmpv6", "icmp", "icmpv6", false},
		{"icmpv6 not icmp", "icmpv6", "icmp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocolMatches(tt.ruleProtocol, tt.destProtocol)
			if got != tt.want {
				t.Errorf("protocolMatches(%s, %s) = %v, want %v", tt.ruleProtocol, tt.destProtocol, got, tt.want)
			}
		})
	}
}

func TestPortInRange(t *testing.T) {
	tests := []struct {
		name     string
		port     int
		fromPort int
		toPort   int
		want     bool
	}{
		{"all ports", 443, 0, 0, true},
		{"exact match", 443, 443, 443, true},
		{"in range", 8080, 8000, 9000, true},
		{"below range", 80, 443, 443, false},
		{"above range", 9000, 443, 443, false},
		{"range start", 8000, 8000, 9000, true},
		{"range end", 9000, 8000, 9000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := portInRange(tt.port, tt.fromPort, tt.toPort)
			if got != tt.want {
				t.Errorf("portInRange(%d, %d, %d) = %v, want %v", tt.port, tt.fromPort, tt.toPort, got, tt.want)
			}
		})
	}
}
