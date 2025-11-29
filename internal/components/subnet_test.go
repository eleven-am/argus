package components

import (
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestSubnet_GetNextHops_ReturnsChainedNACLToRouteTable(t *testing.T) {
	client := newMockAWSClient()
	client.nacls["nacl-123"] = &domain.NACLData{
		ID:    "nacl-123",
		VPCID: "vpc-123",
		OutboundRules: []domain.NACLRule{
			{RuleNumber: 100, Protocol: "-1", FromPort: 0, ToPort: 0, CIDRBlock: "0.0.0.0/0", Action: "allow"},
		},
	}
	client.routeTables["rtb-123"] = &domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	subnet := NewSubnet(&domain.SubnetData{
		ID:           "subnet-123",
		VPCID:        "vpc-123",
		CIDRBlock:    "10.0.1.0/24",
		NaclID:       "nacl-123",
		RouteTableID: "rtb-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	hops, err := subnet.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop (NACL chained to RouteTable), got %d", len(hops))
	}

	nacl, ok := hops[0].(*NACL)
	if !ok {
		t.Fatalf("first hop should be NACL, got %T", hops[0])
	}

	if nacl.next == nil {
		t.Fatal("NACL should have RouteTable as next component")
	}

	if _, ok := nacl.next.(*RouteTable); !ok {
		t.Errorf("NACL.next should be RouteTable, got %T", nacl.next)
	}
}

func TestSubnet_GetNextHops_NACLNotFound(t *testing.T) {
	client := newMockAWSClient()
	client.routeTables["rtb-123"] = &domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	subnet := NewSubnet(&domain.SubnetData{
		ID:           "subnet-123",
		VPCID:        "vpc-123",
		NaclID:       "nacl-missing",
		RouteTableID: "rtb-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	_, err := subnet.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for missing NACL")
	}
}

func TestSubnet_GetNextHops_RouteTableNotFound(t *testing.T) {
	client := newMockAWSClient()
	client.nacls["nacl-123"] = &domain.NACLData{
		ID:    "nacl-123",
		VPCID: "vpc-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	subnet := NewSubnet(&domain.SubnetData{
		ID:           "subnet-123",
		VPCID:        "vpc-123",
		NaclID:       "nacl-123",
		RouteTableID: "rtb-missing",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	_, err := subnet.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for missing route table")
	}
}

func TestSubnet_GetNextHops_ClientNotFound(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	subnet := NewSubnet(&domain.SubnetData{
		ID:           "subnet-123",
		VPCID:        "vpc-123",
		NaclID:       "nacl-123",
		RouteTableID: "rtb-123",
	}, "999999999999")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	_, err := subnet.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for missing client")
	}
}

func TestSubnet_GetID(t *testing.T) {
	subnet := NewSubnet(&domain.SubnetData{
		ID: "subnet-abc123",
	}, "111111111111")

	expected := "111111111111:subnet-abc123"
	if subnet.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, subnet.GetID())
	}
}

func TestSubnet_GetAccountID(t *testing.T) {
	subnet := NewSubnet(&domain.SubnetData{}, "222222222222")

	if subnet.GetAccountID() != "222222222222" {
		t.Errorf("expected 222222222222, got %s", subnet.GetAccountID())
	}
}

func TestSubnet_GetRoutingTarget(t *testing.T) {
	subnet := NewSubnet(&domain.SubnetData{}, "111111111111")

	target := subnet.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("subnet should return empty routing target")
	}
}
