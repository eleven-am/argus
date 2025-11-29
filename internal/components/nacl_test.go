package components

import (
	"errors"
	"strings"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestNACL_GetNextHops_Allowed(t *testing.T) {
	rule := domain.NACLRule{
		RuleNumber: 100,
		Protocol:   "tcp",
		FromPort:   443,
		ToPort:     443,
		CIDRBlock:  "10.0.0.0/8",
		Action:     "allow",
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.NACLRule{rule},
		InboundRules:  []domain.NACLRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	hops, err := nacl.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestNACL_GetNextHops_ExplicitDeny(t *testing.T) {
	nacl := NewNACL(&domain.NACLData{
		ID:    "acl-123",
		VPCID: "vpc-abc",
		OutboundRules: []domain.NACLRule{
			{
				RuleNumber: 100,
				Protocol:   "tcp",
				FromPort:   443,
				ToPort:     443,
				CIDRBlock:  "10.0.0.0/8",
				Action:     "deny",
			},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	_, err := nacl.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "rule 100 denies") {
		t.Errorf("expected deny message, got %v", err)
	}
}

func TestNACL_GetNextHops_ImplicitDeny(t *testing.T) {
	nacl := NewNACL(&domain.NACLData{
		ID:    "acl-123",
		VPCID: "vpc-abc",
		OutboundRules: []domain.NACLRule{
			{
				RuleNumber: 100,
				Protocol:   "tcp",
				FromPort:   80,
				ToPort:     80,
				CIDRBlock:  "10.0.0.0/8",
				Action:     "allow",
			},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	_, err := nacl.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "implicit deny") {
		t.Errorf("expected implicit deny message, got %v", err)
	}
}

func TestNACL_GetNextHops_FirstMatchWins_AllowBeforeDeny(t *testing.T) {
	rules := []domain.NACLRule{
		{
			RuleNumber: 100,
			Protocol:   "tcp",
			FromPort:   443,
			ToPort:     443,
			CIDRBlock:  "10.0.0.0/8",
			Action:     "allow",
		},
		{
			RuleNumber: 200,
			Protocol:   "-1",
			FromPort:   0,
			ToPort:     0,
			CIDRBlock:  "0.0.0.0/0",
			Action:     "deny",
		},
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: rules,
		InboundRules:  rules,
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	hops, err := nacl.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestNACL_GetNextHops_FirstMatchWins_DenyBeforeAllow(t *testing.T) {
	nacl := NewNACL(&domain.NACLData{
		ID:    "acl-123",
		VPCID: "vpc-abc",
		OutboundRules: []domain.NACLRule{
			{
				RuleNumber: 100,
				Protocol:   "tcp",
				FromPort:   443,
				ToPort:     443,
				CIDRBlock:  "10.0.0.0/8",
				Action:     "deny",
			},
			{
				RuleNumber: 200,
				Protocol:   "-1",
				FromPort:   0,
				ToPort:     0,
				CIDRBlock:  "0.0.0.0/0",
				Action:     "allow",
			},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	_, err := nacl.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected error due to deny rule, got nil")
	}
}

func TestNACL_GetNextHops_RulesOutOfOrder(t *testing.T) {
	rules := []domain.NACLRule{
		{
			RuleNumber: 200,
			Protocol:   "-1",
			FromPort:   0,
			ToPort:     0,
			CIDRBlock:  "0.0.0.0/0",
			Action:     "deny",
		},
		{
			RuleNumber: 100,
			Protocol:   "tcp",
			FromPort:   443,
			ToPort:     443,
			CIDRBlock:  "10.0.0.0/8",
			Action:     "allow",
		},
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: rules,
		InboundRules:  rules,
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	hops, err := nacl.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected allow (rule 100 before 200), got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestNACL_GetNextHops_AllProtocols(t *testing.T) {
	rule := domain.NACLRule{
		RuleNumber: 100,
		Protocol:   "-1",
		FromPort:   0,
		ToPort:     0,
		CIDRBlock:  "0.0.0.0/0",
		Action:     "allow",
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.NACLRule{rule},
		InboundRules:  []domain.NACLRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "8.8.8.8",
		Port:     53,
		Protocol: "udp",
	}

	hops, err := nacl.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestNACL_GetID(t *testing.T) {
	nacl := NewNACL(&domain.NACLData{
		ID: "acl-123",
	}, "111122223333")

	if nacl.GetID() != "111122223333:acl-123" {
		t.Errorf("expected 111122223333:acl-123, got %s", nacl.GetID())
	}
}

func TestNACL_GetAccountID(t *testing.T) {
	nacl := NewNACL(&domain.NACLData{
		ID: "acl-123",
	}, "111122223333")

	if nacl.GetAccountID() != "111122223333" {
		t.Errorf("expected 111122223333, got %s", nacl.GetAccountID())
	}
}

func TestNACL_GetRoutingTarget(t *testing.T) {
	nacl := NewNACL(&domain.NACLData{
		ID: "acl-123",
	}, "111122223333")

	target := nacl.GetRoutingTarget()

	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("expected empty routing target")
	}
}

func TestNACL_GetNextHops_EmptyRules(t *testing.T) {
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.NACLRule{},
	}, "111122223333")

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	_, err := nacl.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected implicit deny for empty rules")
	}
	if !strings.Contains(err.Error(), "implicit deny") {
		t.Errorf("expected implicit deny message, got %v", err)
	}
}

func TestNACL_GetNextHops_PortRange(t *testing.T) {
	rule := domain.NACLRule{
		RuleNumber: 100,
		Protocol:   "tcp",
		FromPort:   1024,
		ToPort:     65535,
		CIDRBlock:  "0.0.0.0/0",
		Action:     "allow",
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.NACLRule{rule},
		InboundRules:  []domain.NACLRule{rule},
	}, "111122223333")

	tests := []struct {
		name    string
		port    int
		allowed bool
	}{
		{"below ephemeral range", 443, false},
		{"at range start", 1024, true},
		{"in ephemeral range", 32768, true},
		{"at range end", 65535, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: "10.0.1.1", Port: tt.port, Protocol: "tcp"}
			_, err := nacl.GetNextHops(dest, nil)
			if tt.allowed && err != nil {
				t.Errorf("expected allowed, got error: %v", err)
			}
			if !tt.allowed && err == nil {
				t.Error("expected blocked, got allowed")
			}
		})
	}
}

func TestNACL_GetNextHops_ManyRules(t *testing.T) {
	rules := []domain.NACLRule{
		{RuleNumber: 50, Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRBlock: "10.0.0.0/8", Action: "deny"},
		{RuleNumber: 100, Protocol: "tcp", FromPort: 80, ToPort: 80, CIDRBlock: "0.0.0.0/0", Action: "allow"},
		{RuleNumber: 110, Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlock: "0.0.0.0/0", Action: "allow"},
		{RuleNumber: 120, Protocol: "udp", FromPort: 53, ToPort: 53, CIDRBlock: "0.0.0.0/0", Action: "allow"},
		{RuleNumber: 130, Protocol: "tcp", FromPort: 1024, ToPort: 65535, CIDRBlock: "0.0.0.0/0", Action: "allow"},
		{RuleNumber: 32767, Protocol: "-1", FromPort: 0, ToPort: 0, CIDRBlock: "0.0.0.0/0", Action: "deny"},
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: rules,
		InboundRules:  rules,
	}, "111122223333")

	tests := []struct {
		name     string
		ip       string
		port     int
		protocol string
		allowed  bool
	}{
		{"SSH to internal - denied by rule 50", "10.0.1.1", 22, "tcp", false},
		{"SSH to external - denied by rule 32767", "8.8.8.8", 22, "tcp", false},
		{"HTTP allowed", "8.8.8.8", 80, "tcp", true},
		{"HTTPS allowed", "8.8.8.8", 443, "tcp", true},
		{"DNS UDP allowed", "8.8.8.8", 53, "udp", true},
		{"Ephemeral port allowed", "8.8.8.8", 32768, "tcp", true},
		{"Random UDP blocked", "8.8.8.8", 12345, "udp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: tt.port, Protocol: tt.protocol}
			_, err := nacl.GetNextHops(dest, nil)
			if tt.allowed && err != nil {
				t.Errorf("expected allowed, got error: %v", err)
			}
			if !tt.allowed && err == nil {
				t.Error("expected blocked, got allowed")
			}
		})
	}
}

func TestNACL_GetNextHops_RuleNumber32767(t *testing.T) {
	nacl := NewNACL(&domain.NACLData{
		ID:    "acl-123",
		VPCID: "vpc-abc",
		OutboundRules: []domain.NACLRule{
			{RuleNumber: 32767, Protocol: "-1", FromPort: 0, ToPort: 0, CIDRBlock: "0.0.0.0/0", Action: "deny"},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	_, err := nacl.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected deny from rule 32767")
	}
	if !strings.Contains(err.Error(), "rule 32767") {
		t.Errorf("expected rule 32767 in error, got %v", err)
	}
}

func TestNACL_GetNextHops_ICMP(t *testing.T) {
	rule := domain.NACLRule{RuleNumber: 100, Protocol: "icmp", FromPort: -1, ToPort: -1, CIDRBlock: "0.0.0.0/0", Action: "allow"}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.NACLRule{rule},
		InboundRules:  []domain.NACLRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 0, Protocol: "icmp"}
	hops, err := nacl.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected ICMP allowed, got error: %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestNACL_GetNextHops_SpecificCIDRBeforeWildcard(t *testing.T) {
	rules := []domain.NACLRule{
		{RuleNumber: 100, Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlock: "10.0.1.0/24", Action: "deny"},
		{RuleNumber: 200, Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlock: "0.0.0.0/0", Action: "allow"},
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: rules,
		InboundRules:  rules,
	}, "111122223333")

	tests := []struct {
		name    string
		ip      string
		allowed bool
	}{
		{"specific CIDR denied", "10.0.1.50", false},
		{"other IP allowed", "10.0.2.50", true},
		{"external allowed", "8.8.8.8", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: 443, Protocol: "tcp"}
			_, err := nacl.GetNextHops(dest, nil)
			if tt.allowed && err != nil {
				t.Errorf("expected allowed, got error: %v", err)
			}
			if !tt.allowed && err == nil {
				t.Error("expected blocked, got allowed")
			}
		})
	}
}

func TestNACL_GetNextHops_BlockingErrorFormat(t *testing.T) {
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-test-456",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.NACLRule{},
	}, "123456789012")

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	_, err := nacl.GetNextHops(dest, nil)

	var blockErr *domain.BlockingError
	ok := errors.As(err, &blockErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}

	if blockErr.ComponentID != "123456789012:acl-test-456" {
		t.Errorf("expected ComponentID 123456789012:acl-test-456, got %s", blockErr.ComponentID)
	}
}

func TestNACL_GetNextHops_RulesHeavilyOutOfOrder(t *testing.T) {
	rules := []domain.NACLRule{
		{RuleNumber: 500, Protocol: "-1", FromPort: 0, ToPort: 0, CIDRBlock: "0.0.0.0/0", Action: "deny"},
		{RuleNumber: 100, Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlock: "10.0.0.0/8", Action: "allow"},
		{RuleNumber: 300, Protocol: "tcp", FromPort: 80, ToPort: 80, CIDRBlock: "0.0.0.0/0", Action: "allow"},
		{RuleNumber: 50, Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRBlock: "10.0.0.0/8", Action: "deny"},
		{RuleNumber: 200, Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlock: "0.0.0.0/0", Action: "allow"},
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: rules,
		InboundRules:  rules,
	}, "111122223333")

	tests := []struct {
		name         string
		ip           string
		port         int
		allowed      bool
		matchingRule int
	}{
		{"SSH blocked by rule 50", "10.0.1.1", 22, false, 50},
		{"HTTPS to internal allowed by rule 100", "10.0.1.1", 443, true, 100},
		{"HTTPS to external allowed by rule 200", "8.8.8.8", 443, true, 200},
		{"HTTP allowed by rule 300", "8.8.8.8", 80, true, 300},
		{"Random port blocked by rule 500", "8.8.8.8", 12345, false, 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: tt.port, Protocol: "tcp"}
			_, err := nacl.GetNextHops(dest, nil)
			if tt.allowed && err != nil {
				t.Errorf("expected allowed by rule %d, got error: %v", tt.matchingRule, err)
			}
			if !tt.allowed && err == nil {
				t.Errorf("expected blocked by rule %d, got allowed", tt.matchingRule)
			}
		})
	}
}

func TestNACL_GetNextHops_IPv6_Allowed(t *testing.T) {
	rule := domain.NACLRule{
		RuleNumber:    100,
		Protocol:      "tcp",
		FromPort:      443,
		ToPort:        443,
		IPv6CIDRBlock: "2001:db8::/32",
		Action:        "allow",
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.NACLRule{rule},
		InboundRules:  []domain.NACLRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "2001:db8::1",
		Port:     443,
		Protocol: "tcp",
	}

	hops, err := nacl.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestNACL_GetNextHops_IPv6_Denied(t *testing.T) {
	nacl := NewNACL(&domain.NACLData{
		ID:    "acl-123",
		VPCID: "vpc-abc",
		OutboundRules: []domain.NACLRule{
			{
				RuleNumber:    100,
				Protocol:      "tcp",
				FromPort:      443,
				ToPort:        443,
				IPv6CIDRBlock: "2001:db8::/32",
				Action:        "deny",
			},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "2001:db8::1",
		Port:     443,
		Protocol: "tcp",
	}

	_, err := nacl.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestNACL_GetNextHops_IPv6_AllTraffic(t *testing.T) {
	rule := domain.NACLRule{
		RuleNumber:    100,
		Protocol:      "-1",
		FromPort:      0,
		ToPort:        0,
		IPv6CIDRBlock: "::/0",
		Action:        "allow",
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.NACLRule{rule},
		InboundRules:  []domain.NACLRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "2001:db8:abcd:1234::5678",
		Port:     8080,
		Protocol: "tcp",
	}

	hops, err := nacl.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestNACL_GetNextHops_MixedIPv4AndIPv6Rules(t *testing.T) {
	rules := []domain.NACLRule{
		{
			RuleNumber: 100,
			Protocol:   "tcp",
			FromPort:   443,
			ToPort:     443,
			CIDRBlock:  "10.0.0.0/8",
			Action:     "allow",
		},
		{
			RuleNumber:    110,
			Protocol:      "tcp",
			FromPort:      443,
			ToPort:        443,
			IPv6CIDRBlock: "2001:db8::/32",
			Action:        "allow",
		},
	}
	nacl := NewNACL(&domain.NACLData{
		ID:            "acl-123",
		VPCID:         "vpc-abc",
		OutboundRules: rules,
		InboundRules:  rules,
	}, "111122223333")

	tests := []struct {
		name    string
		ip      string
		allowed bool
	}{
		{"IPv4 allowed", "10.0.1.50", true},
		{"IPv6 allowed", "2001:db8::1", true},
		{"IPv4 implicit deny", "192.168.1.1", false},
		{"IPv6 implicit deny", "2001:db9::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: 443, Protocol: "tcp"}
			_, err := nacl.GetNextHops(dest, nil)
			if tt.allowed && err != nil {
				t.Errorf("expected allowed, got error: %v", err)
			}
			if !tt.allowed && err == nil {
				t.Error("expected blocked, got allowed")
			}
		})
	}
}
