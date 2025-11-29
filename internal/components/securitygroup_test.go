package components

import (
	"errors"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestSecurityGroup_GetNextHops_Allowed(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:   "tcp",
		FromPort:   443,
		ToPort:     443,
		CIDRBlocks: []string{"10.0.0.0/8"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	hops, err := sg.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestSecurityGroup_GetNextHops_AllowAll(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:   "-1",
		FromPort:   0,
		ToPort:     0,
		CIDRBlocks: []string{"0.0.0.0/0"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "8.8.8.8",
		Port:     53,
		Protocol: "udp",
	}

	hops, err := sg.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestSecurityGroup_GetNextHops_BlockedByPort(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:   "tcp",
		FromPort:   443,
		ToPort:     443,
		CIDRBlocks: []string{"10.0.0.0/8"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     80,
		Protocol: "tcp",
	}

	_, err := sg.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestSecurityGroup_GetNextHops_BlockedByProtocol(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:   "tcp",
		FromPort:   443,
		ToPort:     443,
		CIDRBlocks: []string{"10.0.0.0/8"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "udp",
	}

	_, err := sg.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestSecurityGroup_GetNextHops_BlockedByCIDR(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:   "tcp",
		FromPort:   443,
		ToPort:     443,
		CIDRBlocks: []string{"10.0.0.0/8"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "192.168.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	_, err := sg.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestSecurityGroup_GetNextHops_MultipleRules(t *testing.T) {
	rules := []domain.SecurityGroupRule{
		{
			Protocol:   "tcp",
			FromPort:   443,
			ToPort:     443,
			CIDRBlocks: []string{"10.0.0.0/8"},
		},
		{
			Protocol:   "tcp",
			FromPort:   80,
			ToPort:     80,
			CIDRBlocks: []string{"192.168.0.0/16"},
		},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: rules,
		InboundRules:  rules,
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "192.168.1.50",
		Port:     80,
		Protocol: "tcp",
	}

	hops, err := sg.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestSecurityGroup_GetID(t *testing.T) {
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID: "sg-123",
	}, "111122223333")

	if sg.GetID() != "111122223333:sg-123" {
		t.Errorf("expected 111122223333:sg-123, got %s", sg.GetID())
	}
}

func TestSecurityGroup_GetAccountID(t *testing.T) {
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID: "sg-123",
	}, "111122223333")

	if sg.GetAccountID() != "111122223333" {
		t.Errorf("expected 111122223333, got %s", sg.GetAccountID())
	}
}

func TestSecurityGroup_GetRoutingTarget(t *testing.T) {
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID: "sg-123",
	}, "111122223333")

	target := sg.GetRoutingTarget()

	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("expected empty routing target")
	}
}

func TestSecurityGroup_GetNextHops_EmptyRules(t *testing.T) {
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{},
		InboundRules:  []domain.SecurityGroupRule{},
	}, "111122223333")

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	_, err := sg.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected error for empty rules")
	}
}

func TestSecurityGroup_GetNextHops_MultipleCIDRsInRule(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:   "tcp",
		FromPort:   443,
		ToPort:     443,
		CIDRBlocks: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	tests := []struct {
		name    string
		ip      string
		allowed bool
	}{
		{"first CIDR match", "10.1.2.3", true},
		{"second CIDR match", "172.16.5.10", true},
		{"third CIDR match", "192.168.1.100", true},
		{"no CIDR match", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: 443, Protocol: "tcp"}
			_, err := sg.GetNextHops(dest, nil)
			if tt.allowed && err != nil {
				t.Errorf("expected allowed, got error: %v", err)
			}
			if !tt.allowed && err == nil {
				t.Error("expected blocked, got allowed")
			}
		})
	}
}

func TestSecurityGroup_GetNextHops_PortRange(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:   "tcp",
		FromPort:   8000,
		ToPort:     9000,
		CIDRBlocks: []string{"0.0.0.0/0"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	tests := []struct {
		name    string
		port    int
		allowed bool
	}{
		{"below range", 7999, false},
		{"at range start", 8000, true},
		{"in range", 8500, true},
		{"at range end", 9000, true},
		{"above range", 9001, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: "10.0.1.1", Port: tt.port, Protocol: "tcp"}
			_, err := sg.GetNextHops(dest, nil)
			if tt.allowed && err != nil {
				t.Errorf("expected allowed, got error: %v", err)
			}
			if !tt.allowed && err == nil {
				t.Error("expected blocked, got allowed")
			}
		})
	}
}

func TestSecurityGroup_GetNextHops_EdgePorts(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:   "tcp",
		FromPort:   0,
		ToPort:     65535,
		CIDRBlocks: []string{"0.0.0.0/0"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	tests := []struct {
		name string
		port int
	}{
		{"port 0", 0},
		{"port 1", 1},
		{"port 80", 80},
		{"port 443", 443},
		{"port 65535", 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: "10.0.1.1", Port: tt.port, Protocol: "tcp"}
			_, err := sg.GetNextHops(dest, nil)
			if err != nil {
				t.Errorf("expected allowed for %s, got error: %v", tt.name, err)
			}
		})
	}
}

func TestSecurityGroup_GetNextHops_ICMPProtocol(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:   "icmp",
		FromPort:   -1,
		ToPort:     -1,
		CIDRBlocks: []string{"0.0.0.0/0"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 0, Protocol: "icmp"}
	_, err := sg.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected ICMP allowed, got error: %v", err)
	}
}

func TestSecurityGroup_GetNextHops_EmptyCIDRBlocks(t *testing.T) {
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:    "sg-123",
		VPCID: "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{
			{
				Protocol:   "tcp",
				FromPort:   443,
				ToPort:     443,
				CIDRBlocks: []string{},
			},
		},
		InboundRules: []domain.SecurityGroupRule{
			{
				Protocol:   "tcp",
				FromPort:   443,
				ToPort:     443,
				CIDRBlocks: []string{},
			},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	_, err := sg.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected error for empty CIDR blocks")
	}
}

func TestSecurityGroup_GetNextHops_FirstMatchingRuleWins(t *testing.T) {
	rules := []domain.SecurityGroupRule{
		{
			Protocol:   "tcp",
			FromPort:   443,
			ToPort:     443,
			CIDRBlocks: []string{"10.0.0.0/8"},
		},
		{
			Protocol:   "tcp",
			FromPort:   80,
			ToPort:     80,
			CIDRBlocks: []string{"10.0.0.0/8"},
		},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: rules,
		InboundRules:  rules,
	}, "111122223333")

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	hops, err := sg.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestSecurityGroup_GetNextHops_BlockingErrorFormat(t *testing.T) {
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-test-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{},
		InboundRules:  []domain.SecurityGroupRule{},
	}, "999888777666")

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	_, err := sg.GetNextHops(dest, nil)

	var blockErr *domain.BlockingError
	ok := errors.As(err, &blockErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}

	if blockErr.ComponentID != "999888777666:sg-test-123" {
		t.Errorf("expected ComponentID 999888777666:sg-test-123, got %s", blockErr.ComponentID)
	}
}

func TestSecurityGroup_GetNextHops_ReferencedSG_Allowed(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:                 "tcp",
		FromPort:                 443,
		ToPort:                   443,
		ReferencedSecurityGroups: []string{"sg-target"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-source",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	mockClient := newMockAWSClient()
	mockClient.enisBySG["sg-target"] = []domain.ENIData{
		{ID: "eni-1", PrivateIP: "10.0.1.50", PrivateIPs: []string{"10.0.1.50"}},
		{ID: "eni-2", PrivateIP: "10.0.1.51", PrivateIPs: []string{"10.0.1.51"}},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111122223333", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	hops, err := sg.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Errorf("expected allowed via SG reference, got error: %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestSecurityGroup_GetNextHops_ReferencedSG_Blocked(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:                 "tcp",
		FromPort:                 443,
		ToPort:                   443,
		ReferencedSecurityGroups: []string{"sg-target"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-source",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	mockClient := newMockAWSClient()
	mockClient.enisBySG["sg-target"] = []domain.ENIData{
		{ID: "eni-1", PrivateIP: "10.0.1.100", PrivateIPs: []string{"10.0.1.100"}},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111122223333", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	_, err := sg.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Error("expected blocked, IP not in referenced SG")
	}
}

func TestSecurityGroup_GetNextHops_ReferencedSG_SecondaryIP(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:                 "tcp",
		FromPort:                 443,
		ToPort:                   443,
		ReferencedSecurityGroups: []string{"sg-target"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-source",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	mockClient := newMockAWSClient()
	mockClient.enisBySG["sg-target"] = []domain.ENIData{
		{ID: "eni-1", PrivateIP: "10.0.1.100", PrivateIPs: []string{"10.0.1.100", "10.0.1.50", "10.0.1.101"}},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111122223333", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	hops, err := sg.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Errorf("expected allowed via secondary IP, got error: %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestSecurityGroup_GetNextHops_ReferencedSG_MultipleSGs(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:                 "tcp",
		FromPort:                 443,
		ToPort:                   443,
		ReferencedSecurityGroups: []string{"sg-target-1", "sg-target-2"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-source",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	mockClient := newMockAWSClient()
	mockClient.enisBySG["sg-target-1"] = []domain.ENIData{
		{ID: "eni-1", PrivateIP: "10.0.1.100", PrivateIPs: []string{"10.0.1.100"}},
	}
	mockClient.enisBySG["sg-target-2"] = []domain.ENIData{
		{ID: "eni-2", PrivateIP: "10.0.1.50", PrivateIPs: []string{"10.0.1.50"}},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111122223333", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	hops, err := sg.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Errorf("expected allowed via second SG reference, got error: %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestSecurityGroup_GetNextHops_CIDRAndSGReference(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:                 "tcp",
		FromPort:                 443,
		ToPort:                   443,
		CIDRBlocks:               []string{"192.168.0.0/16"},
		ReferencedSecurityGroups: []string{"sg-target"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-source",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	mockClient := newMockAWSClient()
	mockClient.enisBySG["sg-target"] = []domain.ENIData{
		{ID: "eni-1", PrivateIP: "10.0.1.50", PrivateIPs: []string{"10.0.1.50"}},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111122223333", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tests := []struct {
		name    string
		ip      string
		allowed bool
	}{
		{"CIDR match", "192.168.1.50", true},
		{"SG reference match", "10.0.1.50", true},
		{"no match", "172.16.1.50", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: 443, Protocol: "tcp"}
			_, err := sg.GetNextHops(dest, analyzerCtx)
			if tt.allowed && err != nil {
				t.Errorf("expected allowed, got error: %v", err)
			}
			if !tt.allowed && err == nil {
				t.Error("expected blocked, got allowed")
			}
		})
	}
}

func TestSecurityGroup_GetNextHops_PrefixList_Allowed(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:      "tcp",
		FromPort:      443,
		ToPort:        443,
		PrefixListIDs: []string{"pl-s3"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-source",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	mockClient := newMockAWSClient()
	mockClient.prefixLists["pl-s3"] = &domain.ManagedPrefixListData{
		ID:   "pl-s3",
		Name: "com.amazonaws.us-east-1.s3",
		Entries: []domain.PrefixListEntry{
			{CIDR: "52.216.0.0/15"},
			{CIDR: "54.231.0.0/16"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111122223333", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	dest := domain.RoutingTarget{IP: "52.216.100.50", Port: 443, Protocol: "tcp"}
	hops, err := sg.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Errorf("expected allowed via prefix list, got error: %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestSecurityGroup_GetNextHops_PrefixList_Blocked(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:      "tcp",
		FromPort:      443,
		ToPort:        443,
		PrefixListIDs: []string{"pl-s3"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-source",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	mockClient := newMockAWSClient()
	mockClient.prefixLists["pl-s3"] = &domain.ManagedPrefixListData{
		ID:   "pl-s3",
		Name: "com.amazonaws.us-east-1.s3",
		Entries: []domain.PrefixListEntry{
			{CIDR: "52.216.0.0/15"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111122223333", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	_, err := sg.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Error("expected blocked, IP not in prefix list")
	}
}

func TestSecurityGroup_GetNextHops_PrefixList_MultipleLists(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:      "tcp",
		FromPort:      443,
		ToPort:        443,
		PrefixListIDs: []string{"pl-s3", "pl-dynamodb"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-source",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	mockClient := newMockAWSClient()
	mockClient.prefixLists["pl-s3"] = &domain.ManagedPrefixListData{
		ID:      "pl-s3",
		Entries: []domain.PrefixListEntry{{CIDR: "52.216.0.0/15"}},
	}
	mockClient.prefixLists["pl-dynamodb"] = &domain.ManagedPrefixListData{
		ID:      "pl-dynamodb",
		Entries: []domain.PrefixListEntry{{CIDR: "52.94.0.0/22"}},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111122223333", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tests := []struct {
		name    string
		ip      string
		allowed bool
	}{
		{"S3 prefix list match", "52.216.100.50", true},
		{"DynamoDB prefix list match", "52.94.1.50", true},
		{"no match", "10.0.1.50", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: 443, Protocol: "tcp"}
			_, err := sg.GetNextHops(dest, analyzerCtx)
			if tt.allowed && err != nil {
				t.Errorf("expected allowed, got error: %v", err)
			}
			if !tt.allowed && err == nil {
				t.Error("expected blocked, got allowed")
			}
		})
	}
}

func TestSecurityGroup_GetNextHops_IPv6_Allowed(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:       "tcp",
		FromPort:       443,
		ToPort:         443,
		IPv6CIDRBlocks: []string{"2001:db8::/32"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "2001:db8::1",
		Port:     443,
		Protocol: "tcp",
	}

	hops, err := sg.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestSecurityGroup_GetNextHops_IPv6_Blocked(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:       "tcp",
		FromPort:       443,
		ToPort:         443,
		IPv6CIDRBlocks: []string{"2001:db8::/32"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "2001:db9::1",
		Port:     443,
		Protocol: "tcp",
	}

	_, err := sg.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestSecurityGroup_GetNextHops_IPv6_AllTraffic(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:       "-1",
		FromPort:       0,
		ToPort:         0,
		IPv6CIDRBlocks: []string{"::/0"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "2001:db8:abcd:1234::5678",
		Port:     8080,
		Protocol: "tcp",
	}

	hops, err := sg.GetNextHops(dest, nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected empty hops, got %d", len(hops))
	}
}

func TestSecurityGroup_GetNextHops_MixedIPv4AndIPv6(t *testing.T) {
	rule := domain.SecurityGroupRule{
		Protocol:       "tcp",
		FromPort:       443,
		ToPort:         443,
		CIDRBlocks:     []string{"10.0.0.0/8"},
		IPv6CIDRBlocks: []string{"2001:db8::/32"},
	}
	sg := NewSecurityGroup(&domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-abc",
		OutboundRules: []domain.SecurityGroupRule{rule},
		InboundRules:  []domain.SecurityGroupRule{rule},
	}, "111122223333")

	tests := []struct {
		name    string
		ip      string
		allowed bool
	}{
		{"IPv4 allowed", "10.0.1.50", true},
		{"IPv6 allowed", "2001:db8::1", true},
		{"IPv4 blocked", "192.168.1.1", false},
		{"IPv6 blocked", "2001:db9::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: 443, Protocol: "tcp"}
			_, err := sg.GetNextHops(dest, nil)
			if tt.allowed && err != nil {
				t.Errorf("expected allowed, got error: %v", err)
			}
			if !tt.allowed && err == nil {
				t.Error("expected blocked, got allowed")
			}
		})
	}
}
