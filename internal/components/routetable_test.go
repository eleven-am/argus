package components

import (
	"errors"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestRouteTable_GetNextHops_LocalRoute(t *testing.T) {
	client := newMockAWSClient()
	client.vpcs["vpc-123"] = &domain.VPCData{
		ID:        "vpc-123",
		CIDRBlock: "10.0.0.0/16",
	}
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "10.0.0.0/16", PrefixLength: 16, TargetType: "local", TargetID: "local"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("local route should return 1 hop (IPTarget), got %d", len(hops))
	}

	ipTarget, ok := hops[0].(*IPTarget)
	if !ok {
		t.Fatalf("expected IPTarget, got %T", hops[0])
	}

	if ipTarget.GetRoutingTarget().IP != dest.IP {
		t.Errorf("expected IP %s, got %s", dest.IP, ipTarget.GetRoutingTarget().IP)
	}
}

func TestRouteTable_GetNextHops_NoMatchingRoute(t *testing.T) {
	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "10.0.0.0/16", PrefixLength: 16, TargetType: "local", TargetID: "local"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "192.168.1.100", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, nil)

	if err == nil {
		t.Fatal("expected error for no matching route")
	}

	var blockErr *domain.BlockingError
	ok := errors.As(err, &blockErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}

	if blockErr.Reason != "no route to 192.168.1.100" {
		t.Errorf("unexpected reason: %s", blockErr.Reason)
	}
}

func TestRouteTable_GetNextHops_LongestPrefixMatch(t *testing.T) {
	client := newMockAWSClient()
	client.igws["igw-general"] = &domain.InternetGatewayData{ID: "igw-general", VPCID: "vpc-123"}
	client.igws["igw-specific"] = &domain.InternetGatewayData{ID: "igw-specific", VPCID: "vpc-123"}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "internet-gateway", TargetID: "igw-general"},
			{DestinationCIDR: "8.8.8.0/24", PrefixLength: 24, TargetType: "internet-gateway", TargetID: "igw-specific"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 53, Protocol: "udp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	igw, ok := hops[0].(*InternetGateway)
	if !ok {
		t.Fatalf("expected InternetGateway, got %T", hops[0])
	}

	if igw.data.ID != "igw-specific" {
		t.Errorf("expected igw-specific (longer prefix), got %s", igw.data.ID)
	}
}

func TestRouteTable_GetNextHops_InternetGateway(t *testing.T) {
	client := newMockAWSClient()
	client.igws["igw-123"] = &domain.InternetGatewayData{ID: "igw-123", VPCID: "vpc-123"}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "internet-gateway", TargetID: "igw-123"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	if _, ok := hops[0].(*InternetGateway); !ok {
		t.Errorf("expected InternetGateway, got %T", hops[0])
	}
}

func TestRouteTable_GetNextHops_NATGateway(t *testing.T) {
	client := newMockAWSClient()
	client.natGateways["nat-123"] = &domain.NATGatewayData{ID: "nat-123", SubnetID: "subnet-123"}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "nat-gateway", TargetID: "nat-123"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	if _, ok := hops[0].(*NATGateway); !ok {
		t.Errorf("expected NATGateway, got %T", hops[0])
	}
}

func TestRouteTable_GetNextHops_VPCEndpoint(t *testing.T) {
	client := newMockAWSClient()
	client.vpcEndpoints["vpce-123"] = &domain.VPCEndpointData{ID: "vpce-123", VPCID: "vpc-123", ServiceName: "com.amazonaws.us-east-1.s3"}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "52.216.0.0/15", PrefixLength: 15, TargetType: "vpc-endpoint", TargetID: "vpce-123"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "52.216.1.100", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	if _, ok := hops[0].(*VPCEndpoint); !ok {
		t.Errorf("expected VPCEndpoint, got %T", hops[0])
	}
}

func TestRouteTable_GetNextHops_VPCPeering(t *testing.T) {
	client := newMockAWSClient()
	client.vpcPeerings["pcx-123"] = &domain.VPCPeeringData{
		ID:             "pcx-123",
		RequesterVPC:   "vpc-123",
		RequesterOwner: "111111111111",
		AccepterVPC:    "vpc-456",
		AccepterOwner:  "222222222222",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "10.1.0.0/16", PrefixLength: 16, TargetType: "vpc-peering", TargetID: "pcx-123"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.1.1.100", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	if _, ok := hops[0].(*VPCPeering); !ok {
		t.Errorf("expected VPCPeering, got %T", hops[0])
	}
}

func TestRouteTable_GetNextHops_TransitGateway(t *testing.T) {
	client := newMockAWSClient()
	client.tgwAttachments["vpc-123:tgw-123"] = &domain.TGWAttachmentData{
		ID:               "tgw-attach-123",
		TransitGatewayID: "tgw-123",
		TGWAccountID:     "000000000000",
		VPCID:            "vpc-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "10.0.0.0/8", PrefixLength: 8, TargetType: "transit-gateway", TargetID: "tgw-123"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	if _, ok := hops[0].(*TransitGatewayAttachment); !ok {
		t.Errorf("expected TransitGatewayAttachment, got %T", hops[0])
	}
}

func TestRouteTable_GetNextHops_UnknownTargetType(t *testing.T) {
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", newMockAWSClient())
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "unknown-type", TargetID: "xxx"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for unknown target type")
	}

	var blockErr *domain.BlockingError
	ok := errors.As(err, &blockErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}

	if blockErr.Reason != "unknown route target type: unknown-type" {
		t.Errorf("unexpected reason: %s", blockErr.Reason)
	}
}

func TestRouteTable_GetID(t *testing.T) {
	rt := NewRouteTable(&domain.RouteTableData{ID: "rtb-abc123"}, "111111111111")

	expected := "111111111111:rtb-abc123"
	if rt.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, rt.GetID())
	}
}

func TestRouteTable_GetAccountID(t *testing.T) {
	rt := NewRouteTable(&domain.RouteTableData{}, "222222222222")

	if rt.GetAccountID() != "222222222222" {
		t.Errorf("expected 222222222222, got %s", rt.GetAccountID())
	}
}

func TestRouteTable_GetRoutingTarget(t *testing.T) {
	rt := NewRouteTable(&domain.RouteTableData{}, "111111111111")

	target := rt.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("route table should return empty routing target")
	}
}

func TestRouteTable_GetNextHops_EmptyRoutes(t *testing.T) {
	rt := NewRouteTable(&domain.RouteTableData{
		ID:     "rtb-123",
		VPCID:  "vpc-123",
		Routes: []domain.Route{},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, nil)

	if err == nil {
		t.Fatal("expected error for empty routes")
	}
}

func TestRouteTable_GetNextHops_MultipleRoutesFirstMatch(t *testing.T) {
	client := newMockAWSClient()
	client.igws["igw-first"] = &domain.InternetGatewayData{ID: "igw-first", VPCID: "vpc-123"}
	client.igws["igw-second"] = &domain.InternetGatewayData{ID: "igw-second", VPCID: "vpc-123"}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "internet-gateway", TargetID: "igw-first"},
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "internet-gateway", TargetID: "igw-second"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	igw := hops[0].(*InternetGateway)
	if igw.data.ID != "igw-first" {
		t.Errorf("expected igw-first (first match), got %s", igw.data.ID)
	}
}

func TestRouteTable_GetNextHops_IGWNotFound(t *testing.T) {
	client := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "internet-gateway", TargetID: "igw-nonexistent"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for IGW not found")
	}
}

func TestRouteTable_GetNextHops_NATNotFound(t *testing.T) {
	client := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "nat-gateway", TargetID: "nat-nonexistent"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for NAT not found")
	}
}

func TestRouteTable_GetNextHops_VPCEndpointNotFound(t *testing.T) {
	client := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "52.0.0.0/8", PrefixLength: 8, TargetType: "vpc-endpoint", TargetID: "vpce-nonexistent"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "52.1.2.3", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for VPC endpoint not found")
	}
}

func TestRouteTable_GetNextHops_VPCPeeringNotFound(t *testing.T) {
	client := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "10.1.0.0/16", PrefixLength: 16, TargetType: "vpc-peering", TargetID: "pcx-nonexistent"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.1.1.100", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for VPC peering not found")
	}
}

func TestRouteTable_GetNextHops_TGWAttachmentNotFound(t *testing.T) {
	client := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "10.0.0.0/8", PrefixLength: 8, TargetType: "transit-gateway", TargetID: "tgw-nonexistent"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for TGW attachment not found")
	}
}

func TestRouteTable_GetNextHops_ClientNotFound(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "internet-gateway", TargetID: "igw-123"},
		},
	}, "999999999999")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for client not found")
	}
}

func TestRouteTable_GetNextHops_SpecificCIDRMatches(t *testing.T) {
	client := newMockAWSClient()
	client.vpcs["vpc-123"] = &domain.VPCData{
		ID:        "vpc-123",
		CIDRBlock: "192.168.1.0/24",
	}
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "192.168.1.0/24", PrefixLength: 24, TargetType: "local", TargetID: "local"},
		},
	}, "111111111111")

	tests := []struct {
		name    string
		ip      string
		matches bool
	}{
		{"first IP in range", "192.168.1.0", true},
		{"middle IP in range", "192.168.1.128", true},
		{"last IP in range", "192.168.1.255", true},
		{"IP before range", "192.168.0.255", false},
		{"IP after range", "192.168.2.0", false},
		{"completely different", "10.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: 443, Protocol: "tcp"}
			_, err := rt.GetNextHops(dest, analyzerCtx)
			if tt.matches && err != nil {
				t.Errorf("expected match for %s, got error: %v", tt.ip, err)
			}
			if !tt.matches && err == nil {
				t.Errorf("expected no match for %s, got match", tt.ip)
			}
		})
	}
}

func TestRouteTable_GetNextHops_BlockingErrorFormat(t *testing.T) {
	rt := NewRouteTable(&domain.RouteTableData{
		ID:     "rtb-test-456",
		VPCID:  "vpc-123",
		Routes: []domain.Route{},
	}, "888777666555")

	dest := domain.RoutingTarget{IP: "10.0.1.50", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, nil)

	var blockErr *domain.BlockingError
	ok := errors.As(err, &blockErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}

	if blockErr.ComponentID != "888777666555:rtb-test-456" {
		t.Errorf("expected ComponentID 888777666555:rtb-test-456, got %s", blockErr.ComponentID)
	}
}

func TestRouteTable_GetNextHops_VGW(t *testing.T) {
	client := newMockAWSClient()
	client.vgws["vgw-123"] = &domain.VirtualPrivateGatewayData{
		ID:    "vgw-123",
		VPCID: "vpc-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "192.168.0.0/16", PrefixLength: 16, TargetType: "vpn-gateway", TargetID: "vgw-123"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "192.168.1.100", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	vgw, ok := hops[0].(*VirtualPrivateGateway)
	if !ok {
		t.Fatalf("expected VirtualPrivateGateway, got %T", hops[0])
	}

	if vgw.data.ID != "vgw-123" {
		t.Errorf("expected vgw-123, got %s", vgw.data.ID)
	}
}

func TestRouteTable_GetNextHops_VGWNotFound(t *testing.T) {
	client := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "192.168.0.0/16", PrefixLength: 16, TargetType: "vpn-gateway", TargetID: "vgw-nonexistent"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "192.168.1.100", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for VGW not found")
	}
}

func TestRouteTable_GetNextHops_VGW_LongestPrefixMatch(t *testing.T) {
	client := newMockAWSClient()
	client.vgws["vgw-general"] = &domain.VirtualPrivateGatewayData{ID: "vgw-general", VPCID: "vpc-123"}
	client.vgws["vgw-specific"] = &domain.VirtualPrivateGatewayData{ID: "vgw-specific", VPCID: "vpc-123"}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "192.168.0.0/16", PrefixLength: 16, TargetType: "vpn-gateway", TargetID: "vgw-general"},
			{DestinationCIDR: "192.168.1.0/24", PrefixLength: 24, TargetType: "vpn-gateway", TargetID: "vgw-specific"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "192.168.1.50", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	vgw := hops[0].(*VirtualPrivateGateway)
	if vgw.data.ID != "vgw-specific" {
		t.Errorf("expected vgw-specific (longer prefix), got %s", vgw.data.ID)
	}
}

func TestRouteTable_GetNextHops_PrefixList_Allowed(t *testing.T) {
	client := newMockAWSClient()
	client.igws["igw-123"] = &domain.InternetGatewayData{ID: "igw-123", VPCID: "vpc-123"}
	client.prefixLists["pl-s3"] = &domain.ManagedPrefixListData{
		ID:   "pl-s3",
		Name: "com.amazonaws.us-east-1.s3",
		Entries: []domain.PrefixListEntry{
			{CIDR: "52.216.0.0/15"},
			{CIDR: "54.231.0.0/16"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationPrefixListID: "pl-s3", TargetType: "internet-gateway", TargetID: "igw-123"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "52.216.1.100", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	if _, ok := hops[0].(*InternetGateway); !ok {
		t.Errorf("expected InternetGateway, got %T", hops[0])
	}
}

func TestRouteTable_GetNextHops_PrefixList_NoMatch(t *testing.T) {
	client := newMockAWSClient()
	client.prefixLists["pl-s3"] = &domain.ManagedPrefixListData{
		ID:   "pl-s3",
		Name: "com.amazonaws.us-east-1.s3",
		Entries: []domain.PrefixListEntry{
			{CIDR: "52.216.0.0/15"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationPrefixListID: "pl-s3", TargetType: "internet-gateway", TargetID: "igw-123"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for no matching route")
	}

	var blockErr *domain.BlockingError
	ok := errors.As(err, &blockErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}

	if blockErr.Reason != "no route to 8.8.8.8" {
		t.Errorf("unexpected reason: %s", blockErr.Reason)
	}
}

func TestRouteTable_GetNextHops_PrefixList_LongestPrefixMatch(t *testing.T) {
	client := newMockAWSClient()
	client.igws["igw-general"] = &domain.InternetGatewayData{ID: "igw-general", VPCID: "vpc-123"}
	client.igws["igw-specific"] = &domain.InternetGatewayData{ID: "igw-specific", VPCID: "vpc-123"}
	client.prefixLists["pl-general"] = &domain.ManagedPrefixListData{
		ID:   "pl-general",
		Name: "general-list",
		Entries: []domain.PrefixListEntry{
			{CIDR: "52.0.0.0/8"},
		},
	}
	client.prefixLists["pl-specific"] = &domain.ManagedPrefixListData{
		ID:   "pl-specific",
		Name: "specific-list",
		Entries: []domain.PrefixListEntry{
			{CIDR: "52.216.0.0/15"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationPrefixListID: "pl-general", TargetType: "internet-gateway", TargetID: "igw-general"},
			{DestinationPrefixListID: "pl-specific", TargetType: "internet-gateway", TargetID: "igw-specific"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "52.216.1.100", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	igw, ok := hops[0].(*InternetGateway)
	if !ok {
		t.Fatalf("expected InternetGateway, got %T", hops[0])
	}

	if igw.data.ID != "igw-specific" {
		t.Errorf("expected igw-specific (longer prefix), got %s", igw.data.ID)
	}
}

func TestRouteTable_GetNextHops_PrefixList_NotFound(t *testing.T) {
	client := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationPrefixListID: "pl-nonexistent", TargetType: "internet-gateway", TargetID: "igw-123"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "52.216.1.100", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for prefix list not found")
	}
}

func TestRouteTable_GetNextHops_PrefixList_MultipleEntries(t *testing.T) {
	client := newMockAWSClient()
	client.igws["igw-123"] = &domain.InternetGatewayData{ID: "igw-123", VPCID: "vpc-123"}
	client.prefixLists["pl-multi"] = &domain.ManagedPrefixListData{
		ID:   "pl-multi",
		Name: "multi-entry-list",
		Entries: []domain.PrefixListEntry{
			{CIDR: "10.0.0.0/8"},
			{CIDR: "172.16.0.0/12"},
			{CIDR: "192.168.0.0/16"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationPrefixListID: "pl-multi", TargetType: "internet-gateway", TargetID: "igw-123"},
		},
	}, "111111111111")

	tests := []struct {
		name    string
		ip      string
		matches bool
	}{
		{"matches first entry", "10.1.2.3", true},
		{"matches second entry", "172.20.1.1", true},
		{"matches third entry", "192.168.1.50", true},
		{"no match", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: 443, Protocol: "tcp"}
			_, err := rt.GetNextHops(dest, analyzerCtx)
			if tt.matches && err != nil {
				t.Errorf("expected match for %s, got error: %v", tt.ip, err)
			}
			if !tt.matches && err == nil {
				t.Errorf("expected no match for %s, got match", tt.ip)
			}
		})
	}
}

func TestRouteTable_GetNextHops_MixedCIDRAndPrefixList(t *testing.T) {
	client := newMockAWSClient()
	client.igws["igw-cidr"] = &domain.InternetGatewayData{ID: "igw-cidr", VPCID: "vpc-123"}
	client.igws["igw-pl"] = &domain.InternetGatewayData{ID: "igw-pl", VPCID: "vpc-123"}
	client.prefixLists["pl-test"] = &domain.ManagedPrefixListData{
		ID:   "pl-test",
		Name: "test-list",
		Entries: []domain.PrefixListEntry{
			{CIDR: "10.0.0.0/8"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "internet-gateway", TargetID: "igw-cidr"},
			{DestinationPrefixListID: "pl-test", TargetType: "internet-gateway", TargetID: "igw-pl"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.1.2.3", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	igw, ok := hops[0].(*InternetGateway)
	if !ok {
		t.Fatalf("expected InternetGateway, got %T", hops[0])
	}

	if igw.data.ID != "igw-pl" {
		t.Errorf("expected igw-pl (prefix list has longer prefix /8 vs /0), got %s", igw.data.ID)
	}
}

func TestRouteTable_GetNextHops_IPv6_LocalRoute(t *testing.T) {
	client := newMockAWSClient()
	client.vpcs["vpc-123"] = &domain.VPCData{
		ID:            "vpc-123",
		IPv6CIDRBlock: "2001:db8::/32",
	}
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationIPv6CIDR: "2001:db8::/32", TargetType: "local", TargetID: "local"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "2001:db8::1", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("local route should return 1 hop (IPTarget), got %d", len(hops))
	}

	ipTarget, ok := hops[0].(*IPTarget)
	if !ok {
		t.Fatalf("expected IPTarget, got %T", hops[0])
	}

	if ipTarget.GetRoutingTarget().IP != dest.IP {
		t.Errorf("expected IP %s, got %s", dest.IP, ipTarget.GetRoutingTarget().IP)
	}
}

func TestRouteTable_GetNextHops_IPv6_InternetGateway(t *testing.T) {
	client := newMockAWSClient()
	client.igws["igw-123"] = &domain.InternetGatewayData{ID: "igw-123", VPCID: "vpc-123"}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationIPv6CIDR: "::/0", TargetType: "internet-gateway", TargetID: "igw-123"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "2001:db8::1", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	if _, ok := hops[0].(*InternetGateway); !ok {
		t.Errorf("expected InternetGateway, got %T", hops[0])
	}
}

func TestRouteTable_GetNextHops_IPv6_NoMatchingRoute(t *testing.T) {
	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationIPv6CIDR: "2001:db8::/32", TargetType: "local", TargetID: "local"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "2001:db9::1", Port: 443, Protocol: "tcp"}
	_, err := rt.GetNextHops(dest, nil)

	if err == nil {
		t.Fatal("expected error for no matching route")
	}
}

func TestRouteTable_GetNextHops_MixedIPv4AndIPv6(t *testing.T) {
	client := newMockAWSClient()
	client.igws["igw-v4"] = &domain.InternetGatewayData{ID: "igw-v4", VPCID: "vpc-123"}
	client.igws["igw-v6"] = &domain.InternetGatewayData{ID: "igw-v6", VPCID: "vpc-123"}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "internet-gateway", TargetID: "igw-v4"},
			{DestinationIPv6CIDR: "::/0", TargetType: "internet-gateway", TargetID: "igw-v6"},
		},
	}, "111111111111")

	tests := []struct {
		name        string
		ip          string
		expectedIGW string
	}{
		{"IPv4 to igw-v4", "8.8.8.8", "igw-v4"},
		{"IPv6 to igw-v6", "2001:db8::1", "igw-v6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := domain.RoutingTarget{IP: tt.ip, Port: 443, Protocol: "tcp"}
			hops, err := rt.GetNextHops(dest, analyzerCtx)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(hops) != 1 {
				t.Fatalf("expected 1 hop, got %d", len(hops))
			}

			igw, ok := hops[0].(*InternetGateway)
			if !ok {
				t.Fatalf("expected InternetGateway, got %T", hops[0])
			}

			if igw.data.ID != tt.expectedIGW {
				t.Errorf("expected %s, got %s", tt.expectedIGW, igw.data.ID)
			}
		})
	}
}

func TestRouteTable_GetNextHops_IPv6_LongestPrefixMatch(t *testing.T) {
	client := newMockAWSClient()
	client.igws["igw-general"] = &domain.InternetGatewayData{ID: "igw-general", VPCID: "vpc-123"}
	client.igws["igw-specific"] = &domain.InternetGatewayData{ID: "igw-specific", VPCID: "vpc-123"}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rt := NewRouteTable(&domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
		Routes: []domain.Route{
			{DestinationIPv6CIDR: "::/0", TargetType: "internet-gateway", TargetID: "igw-general"},
			{DestinationIPv6CIDR: "2001:db8::/32", TargetType: "internet-gateway", TargetID: "igw-specific"},
		},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "2001:db8::1", Port: 443, Protocol: "tcp"}
	hops, err := rt.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	igw, ok := hops[0].(*InternetGateway)
	if !ok {
		t.Fatalf("expected InternetGateway, got %T", hops[0])
	}

	if igw.data.ID != "igw-specific" {
		t.Errorf("expected igw-specific (longer prefix), got %s", igw.data.ID)
	}
}
