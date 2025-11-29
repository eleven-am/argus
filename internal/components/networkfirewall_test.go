package components

import (
	"errors"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestNetworkFirewall_GetNextHops_StatelessPass(t *testing.T) {
	nf := NewNetworkFirewall(&domain.NetworkFirewallData{
		ID:    "nfw-123",
		VPCID: "vpc-abc",
		StatelessRuleGroups: []domain.StatelessRuleGroup{
			{
				Priority: 1,
				Rules: []domain.StatelessRule{
					{
						Priority: 1,
						Actions:  []string{"aws:pass"},
						Match: domain.StatelessMatch{
							Protocols:    []int{6},
							Destinations: []string{"10.0.0.0/8"},
							DestPorts:    []domain.PortRangeSpec{{From: 443, To: 443}},
						},
					},
				},
			},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	accountCtx := newMockAccountContext()
	client := newMockAWSClient()
	client.vpcs["vpc-abc"] = &domain.VPCData{
		ID:               "vpc-abc",
		MainRouteTableID: "rtb-main",
	}
	client.routeTables["rtb-main"] = &domain.RouteTableData{
		ID:    "rtb-main",
		VPCID: "vpc-abc",
	}
	accountCtx.addClient("111122223333", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	hops, err := nf.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (route table), got %d", len(hops))
	}
}

func TestNetworkFirewall_GetNextHops_StatelessDrop(t *testing.T) {
	nf := NewNetworkFirewall(&domain.NetworkFirewallData{
		ID:    "nfw-123",
		VPCID: "vpc-abc",
		StatelessRuleGroups: []domain.StatelessRuleGroup{
			{
				Priority: 1,
				Rules: []domain.StatelessRule{
					{
						Priority: 1,
						Actions:  []string{"aws:drop"},
						Match: domain.StatelessMatch{
							Protocols:    []int{6},
							Destinations: []string{"10.0.0.0/8"},
							DestPorts:    []domain.PortRangeSpec{{From: 443, To: 443}},
						},
					},
				},
			},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	_, err := nf.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected blocking error, got nil")
	}

	var blockErr *domain.BlockingError
	if !errors.As(err, &blockErr) {
		t.Errorf("expected BlockingError, got %T", err)
	}
}

func TestNetworkFirewall_GetNextHops_StatefulPass(t *testing.T) {
	nf := NewNetworkFirewall(&domain.NetworkFirewallData{
		ID:    "nfw-123",
		VPCID: "vpc-abc",
		StatelessRuleGroups: []domain.StatelessRuleGroup{
			{
				Priority: 1,
				Rules: []domain.StatelessRule{
					{
						Priority: 1,
						Actions:  []string{"aws:forward_to_sfe"},
						Match: domain.StatelessMatch{
							Destinations: []string{"0.0.0.0/0"},
						},
					},
				},
			},
		},
		StatefulRuleGroups: []domain.StatefulRuleGroup{
			{
				Priority: 1,
				Rules: []domain.StatefulRule{
					{
						Action:      "pass",
						Protocol:    "tcp",
						Destination: "any",
						DestPort:    "443",
					},
				},
			},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	accountCtx := newMockAccountContext()
	client := newMockAWSClient()
	client.vpcs["vpc-abc"] = &domain.VPCData{
		ID:               "vpc-abc",
		MainRouteTableID: "rtb-main",
	}
	client.routeTables["rtb-main"] = &domain.RouteTableData{
		ID:    "rtb-main",
		VPCID: "vpc-abc",
	}
	accountCtx.addClient("111122223333", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	hops, err := nf.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (route table), got %d", len(hops))
	}
}

func TestNetworkFirewall_GetNextHops_StatefulDrop(t *testing.T) {
	nf := NewNetworkFirewall(&domain.NetworkFirewallData{
		ID:    "nfw-123",
		VPCID: "vpc-abc",
		StatelessRuleGroups: []domain.StatelessRuleGroup{
			{
				Priority: 1,
				Rules: []domain.StatelessRule{
					{
						Priority: 1,
						Actions:  []string{"aws:forward_to_sfe"},
						Match: domain.StatelessMatch{
							Destinations: []string{"0.0.0.0/0"},
						},
					},
				},
			},
		},
		StatefulRuleGroups: []domain.StatefulRuleGroup{
			{
				Priority: 1,
				Rules: []domain.StatefulRule{
					{
						Action:      "drop",
						Protocol:    "tcp",
						Destination: "any",
						DestPort:    "443",
					},
				},
			},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	_, err := nf.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected blocking error, got nil")
	}

	var blockErr *domain.BlockingError
	if !errors.As(err, &blockErr) {
		t.Errorf("expected BlockingError, got %T", err)
	}
}

func TestNetworkFirewall_GetNextHops_PriorityOrdering(t *testing.T) {
	nf := NewNetworkFirewall(&domain.NetworkFirewallData{
		ID:    "nfw-123",
		VPCID: "vpc-abc",
		StatelessRuleGroups: []domain.StatelessRuleGroup{
			{
				Priority: 2,
				Rules: []domain.StatelessRule{
					{
						Priority: 1,
						Actions:  []string{"aws:drop"},
						Match: domain.StatelessMatch{
							Destinations: []string{"0.0.0.0/0"},
						},
					},
				},
			},
			{
				Priority: 1,
				Rules: []domain.StatelessRule{
					{
						Priority: 1,
						Actions:  []string{"aws:pass"},
						Match: domain.StatelessMatch{
							Destinations: []string{"10.0.0.0/8"},
						},
					},
				},
			},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	accountCtx := newMockAccountContext()
	client := newMockAWSClient()
	client.vpcs["vpc-abc"] = &domain.VPCData{
		ID:               "vpc-abc",
		MainRouteTableID: "rtb-main",
	}
	client.routeTables["rtb-main"] = &domain.RouteTableData{
		ID:    "rtb-main",
		VPCID: "vpc-abc",
	}
	accountCtx.addClient("111122223333", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	hops, err := nf.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Errorf("expected pass from priority 1 group, got error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop, got %d", len(hops))
	}
}

func TestNetworkFirewall_GetNextHops_StatefulDefaultDrop(t *testing.T) {
	nf := NewNetworkFirewall(&domain.NetworkFirewallData{
		ID:    "nfw-123",
		VPCID: "vpc-abc",
		DefaultActions: domain.FirewallDefaultActions{
			StatefulDefaultActions: []string{"aws:drop_all"},
		},
	}, "111122223333")

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	_, err := nf.GetNextHops(dest, nil)

	if err == nil {
		t.Error("expected blocking error from stateful default drop action, got nil")
	}

	var blockErr *domain.BlockingError
	if !errors.As(err, &blockErr) {
		t.Errorf("expected BlockingError, got %T", err)
	}
}

func TestNetworkFirewall_EvaluateWithDetails(t *testing.T) {
	nf := NewNetworkFirewall(&domain.NetworkFirewallData{
		ID:    "nfw-123",
		VPCID: "vpc-abc",
		StatelessRuleGroups: []domain.StatelessRuleGroup{
			{
				Priority: 1,
				Rules: []domain.StatelessRule{
					{
						Priority: 1,
						Actions:  []string{"aws:pass"},
						Match: domain.StatelessMatch{
							Protocols:    []int{6},
							Destinations: []string{"10.0.0.0/8"},
							DestPorts:    []domain.PortRangeSpec{{From: 443, To: 443}},
						},
					},
					{
						Priority: 2,
						Actions:  []string{"aws:drop"},
						Match: domain.StatelessMatch{
							Protocols:    []int{6},
							Destinations: []string{"0.0.0.0/0"},
						},
					},
				},
			},
		},
	}, "111122223333")

	target := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	result := nf.EvaluateWithDetails(target, "outbound")

	if !result.Allowed {
		t.Error("expected allowed, got blocked")
	}
	if len(result.Evaluations) == 0 {
		t.Error("expected rule evaluations")
	}

	foundMatch := false
	for _, eval := range result.Evaluations {
		if eval.Matched {
			foundMatch = true
			if eval.Action != "pass" {
				t.Errorf("expected pass action, got %s", eval.Action)
			}
		}
	}
	if !foundMatch {
		t.Error("expected at least one matched rule")
	}
}

func TestNetworkFirewall_ProtocolMatching(t *testing.T) {
	tests := []struct {
		name          string
		ruleProtocols []int
		destProtocol  string
		expectMatch   bool
	}{
		{"tcp matches 6", []int{6}, "tcp", true},
		{"udp matches 17", []int{17}, "udp", true},
		{"icmp matches 1", []int{1}, "icmp", true},
		{"icmpv6 matches 58", []int{58}, "icmpv6", true},
		{"tcp rule vs udp traffic", []int{6}, "udp", false},
		{"empty protocols matches all", []int{}, "tcp", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nf := NewNetworkFirewall(&domain.NetworkFirewallData{
				ID:    "nfw-123",
				VPCID: "vpc-abc",
				StatelessRuleGroups: []domain.StatelessRuleGroup{
					{
						Priority: 1,
						Rules: []domain.StatelessRule{
							{
								Priority: 1,
								Actions:  []string{"aws:pass"},
								Match: domain.StatelessMatch{
									Protocols:    tt.ruleProtocols,
									Destinations: []string{"0.0.0.0/0"},
								},
							},
						},
					},
				},
				DefaultActions: domain.FirewallDefaultActions{
					StatelessDefaultActions: []string{"aws:drop"},
					StatefulDefaultActions:  []string{"aws:drop_all"},
				},
			}, "111122223333")

			dest := domain.RoutingTarget{
				IP:       "10.0.1.50",
				Port:     443,
				Protocol: tt.destProtocol,
			}

			accountCtx := newMockAccountContext()
			client := newMockAWSClient()
			client.vpcs["vpc-abc"] = &domain.VPCData{
				ID:               "vpc-abc",
				MainRouteTableID: "rtb-main",
			}
			client.routeTables["rtb-main"] = &domain.RouteTableData{
				ID:    "rtb-main",
				VPCID: "vpc-abc",
			}
			accountCtx.addClient("111122223333", client)
			analyzerCtx := newMockAnalyzerContext(accountCtx)

			_, err := nf.GetNextHops(dest, analyzerCtx)

			if tt.expectMatch {
				if err != nil {
					t.Errorf("expected match (no error), got %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected no match (blocking error), got nil")
				}
			}
		})
	}
}

func TestNetworkFirewall_GetID(t *testing.T) {
	nf := NewNetworkFirewall(&domain.NetworkFirewallData{
		ID:    "nfw-123",
		VPCID: "vpc-abc",
	}, "111122223333")

	id := nf.GetID()
	expected := "111122223333:nfw-123"

	if id != expected {
		t.Errorf("GetID() = %s, want %s", id, expected)
	}
}

func TestNetworkFirewall_GetComponentType(t *testing.T) {
	nf := NewNetworkFirewall(&domain.NetworkFirewallData{
		ID:    "nfw-123",
		VPCID: "vpc-abc",
	}, "111122223333")

	ct := nf.GetComponentType()

	if ct != "NetworkFirewall" {
		t.Errorf("GetComponentType() = %s, want NetworkFirewall", ct)
	}
}

func TestNetworkFirewallEndpoint_GetNextHops(t *testing.T) {
	nfe := NewNetworkFirewallEndpoint("nfw-123", "vpce-123", "subnet-abc", "111122223333")

	accountCtx := newMockAccountContext()
	client := newMockAWSClient()
	client.networkFirewalls["nfw-123"] = &domain.NetworkFirewallData{
		ID:    "nfw-123",
		VPCID: "vpc-abc",
	}
	accountCtx.addClient("111122223333", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	dest := domain.RoutingTarget{
		IP:       "10.0.1.50",
		Port:     443,
		Protocol: "tcp",
	}

	hops, err := nfe.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (NetworkFirewall), got %d", len(hops))
	}
	if hops[0].GetComponentType() != "NetworkFirewall" {
		t.Errorf("expected NetworkFirewall component, got %s", hops[0].GetComponentType())
	}
}

func TestNetworkFirewallEndpoint_GetID(t *testing.T) {
	nfe := NewNetworkFirewallEndpoint("nfw-123", "vpce-123", "subnet-abc", "111122223333")

	id := nfe.GetID()
	expected := "111122223333:vpce-123"

	if id != expected {
		t.Errorf("GetID() = %s, want %s", id, expected)
	}
}

func TestNetworkFirewallEndpoint_GetComponentType(t *testing.T) {
	nfe := NewNetworkFirewallEndpoint("nfw-123", "vpce-123", "subnet-abc", "111122223333")

	ct := nfe.GetComponentType()

	if ct != "NetworkFirewallEndpoint" {
		t.Errorf("GetComponentType() = %s, want NetworkFirewallEndpoint", ct)
	}
}

func TestNetworkFirewallEndpoint_GetSubnetID(t *testing.T) {
	nfe := NewNetworkFirewallEndpoint("nfw-123", "vpce-123", "subnet-abc", "111122223333")

	subnetID := nfe.GetSubnetID()

	if subnetID != "subnet-abc" {
		t.Errorf("GetSubnetID() = %s, want subnet-abc", subnetID)
	}
}
