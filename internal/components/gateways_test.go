package components

import (
	"errors"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestInternetGateway_GetNextHops_ExternalDestination(t *testing.T) {
	igw := NewInternetGateway(&domain.InternetGatewayData{
		ID:    "igw-123",
		VPCID: "vpc-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 443, Protocol: "tcp"}
	hops, err := igw.GetNextHops(dest, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("IGW should return IPTarget for external destination, got %d hops", len(hops))
	}

	ipTarget, ok := hops[0].(*IPTarget)
	if !ok {
		t.Fatalf("expected IPTarget, got %T", hops[0])
	}

	if ipTarget.GetRoutingTarget().IP != dest.IP {
		t.Errorf("expected IP %s, got %s", dest.IP, ipTarget.GetRoutingTarget().IP)
	}
}

func TestInternetGateway_GetNextHops_PrivateDestination(t *testing.T) {
	igw := NewInternetGateway(&domain.InternetGatewayData{
		ID:    "igw-123",
		VPCID: "vpc-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	_, err := igw.GetNextHops(dest, nil)

	if err == nil {
		t.Fatal("expected error for private destination")
	}

	var blockErr *domain.BlockingError
	ok := errors.As(err, &blockErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}

	if blockErr.ComponentID != igw.GetID() {
		t.Errorf("expected component ID %s, got %s", igw.GetID(), blockErr.ComponentID)
	}
}

func TestInternetGateway_GetID(t *testing.T) {
	igw := NewInternetGateway(&domain.InternetGatewayData{ID: "igw-abc"}, "111111111111")

	if igw.GetID() != "111111111111:igw-abc" {
		t.Errorf("unexpected ID: %s", igw.GetID())
	}
}

func TestInternetGateway_GetAccountID(t *testing.T) {
	igw := NewInternetGateway(&domain.InternetGatewayData{}, "222222222222")

	if igw.GetAccountID() != "222222222222" {
		t.Errorf("unexpected account ID: %s", igw.GetAccountID())
	}
}

func TestNATGateway_GetNextHops_ExternalDestination(t *testing.T) {
	nat := NewNATGateway(&domain.NATGatewayData{
		ID:       "nat-123",
		SubnetID: "subnet-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "8.8.8.8", Port: 443, Protocol: "tcp"}
	hops, err := nat.GetNextHops(dest, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("NAT should return IPTarget for external destination, got %d hops", len(hops))
	}

	ipTarget, ok := hops[0].(*IPTarget)
	if !ok {
		t.Fatalf("expected IPTarget, got %T", hops[0])
	}

	if ipTarget.GetRoutingTarget().IP != dest.IP {
		t.Errorf("expected IP %s, got %s", dest.IP, ipTarget.GetRoutingTarget().IP)
	}
}

func TestNATGateway_GetNextHops_PrivateDestination(t *testing.T) {
	nat := NewNATGateway(&domain.NATGatewayData{
		ID:       "nat-123",
		SubnetID: "subnet-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	_, err := nat.GetNextHops(dest, nil)

	if err == nil {
		t.Fatal("expected error for private destination")
	}

	var blockErr *domain.BlockingError
	ok := errors.As(err, &blockErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}

	if blockErr.ComponentID != nat.GetID() {
		t.Errorf("expected component ID %s, got %s", nat.GetID(), blockErr.ComponentID)
	}
}

func TestNATGateway_GetID(t *testing.T) {
	nat := NewNATGateway(&domain.NATGatewayData{ID: "nat-abc"}, "111111111111")

	if nat.GetID() != "111111111111:nat-abc" {
		t.Errorf("unexpected ID: %s", nat.GetID())
	}
}

func TestVPCEndpoint_GetNextHops(t *testing.T) {
	client := newMockAWSClient()
	client.subnets["subnet-1"] = &domain.SubnetData{
		ID:           "subnet-1",
		VPCID:        "vpc-123",
		NaclID:       "nacl-1",
		RouteTableID: "rtb-1",
	}
	client.nacls["nacl-1"] = &domain.NACLData{
		ID: "nacl-1",
		OutboundRules: []domain.NACLRule{
			{RuleNumber: 100, Protocol: "tcp", FromPort: 0, ToPort: 65535, CIDRBlock: "0.0.0.0/0", Action: "allow"},
		},
		InboundRules: []domain.NACLRule{
			{RuleNumber: 100, Protocol: "tcp", FromPort: 0, ToPort: 65535, CIDRBlock: "0.0.0.0/0", Action: "allow"},
		},
	}
	client.routeTables["rtb-1"] = &domain.RouteTableData{
		ID: "rtb-1",
		Routes: []domain.Route{
			{DestinationCIDR: "0.0.0.0/0", PrefixLength: 0, TargetType: "internet-gateway", TargetID: "igw-1"},
		},
	}
	client.igws["igw-1"] = &domain.InternetGatewayData{ID: "igw-1"}
	client.securityGroups["sg-1"] = &domain.SecurityGroupData{
		ID: "sg-1",
		OutboundRules: []domain.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 0, ToPort: 65535, CIDRBlocks: []string{"0.0.0.0/0"}},
		},
		InboundRules: []domain.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 0, ToPort: 65535, CIDRBlocks: []string{"0.0.0.0/0"}},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	endpoint := NewVPCEndpoint(&domain.VPCEndpointData{
		ID:             "vpce-123",
		VPCID:          "vpc-123",
		ServiceName:    "com.amazonaws.us-east-1.s3",
		Type:           "Interface",
		State:          "available",
		SubnetIDs:      []string{"subnet-1"},
		SecurityGroups: []string{"sg-1"},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "52.216.1.100", Port: 443, Protocol: "tcp"}
	hops, err := endpoint.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}
}

func TestVPCEndpoint_GetID(t *testing.T) {
	endpoint := NewVPCEndpoint(&domain.VPCEndpointData{ID: "vpce-abc"}, "111111111111")

	if endpoint.GetID() != "111111111111:vpce-abc" {
		t.Errorf("unexpected ID: %s", endpoint.GetID())
	}
}

func TestVPCPeering_GetNextHops_ToAccepterVPC(t *testing.T) {
	sourceClient := newMockAWSClient()

	accepterClient := newMockAWSClient()
	accepterClient.vpcs["vpc-456"] = &domain.VPCData{
		ID:               "vpc-456",
		CIDRBlock:        "10.1.0.0/16",
		MainRouteTableID: "rtb-456",
	}
	accepterClient.routeTables["rtb-456"] = &domain.RouteTableData{
		ID:    "rtb-456",
		VPCID: "vpc-456",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", sourceClient)
	accountCtx.addClient("222222222222", accepterClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	peering := NewVPCPeering(&domain.VPCPeeringData{
		ID:             "pcx-123",
		RequesterVPC:   "vpc-123",
		RequesterOwner: "111111111111",
		AccepterVPC:    "vpc-456",
		AccepterOwner:  "222222222222",
	}, "111111111111", "vpc-123")

	dest := domain.RoutingTarget{IP: "10.1.1.100", Port: 443, Protocol: "tcp"}
	hops, err := peering.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	rt, ok := hops[0].(*RouteTable)
	if !ok {
		t.Fatalf("expected RouteTable, got %T", hops[0])
	}

	if rt.data.ID != "rtb-456" {
		t.Errorf("expected rtb-456, got %s", rt.data.ID)
	}
}

func TestVPCPeering_GetNextHops_ToRequesterVPC(t *testing.T) {
	requesterClient := newMockAWSClient()
	requesterClient.vpcs["vpc-123"] = &domain.VPCData{
		ID:               "vpc-123",
		CIDRBlock:        "10.0.0.0/16",
		MainRouteTableID: "rtb-123",
	}
	requesterClient.routeTables["rtb-123"] = &domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", requesterClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	peering := NewVPCPeering(&domain.VPCPeeringData{
		ID:             "pcx-123",
		RequesterVPC:   "vpc-123",
		RequesterOwner: "111111111111",
		AccepterVPC:    "vpc-456",
		AccepterOwner:  "222222222222",
	}, "222222222222", "vpc-456")

	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	hops, err := peering.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	rt, ok := hops[0].(*RouteTable)
	if !ok {
		t.Fatalf("expected RouteTable, got %T", hops[0])
	}

	if rt.data.ID != "rtb-123" {
		t.Errorf("expected rtb-123, got %s", rt.data.ID)
	}
}

func TestVPCPeering_GetID(t *testing.T) {
	peering := NewVPCPeering(&domain.VPCPeeringData{ID: "pcx-abc", RequesterOwner: "111111111111"}, "111111111111", "vpc-123")

	if peering.GetID() != "111111111111:pcx-abc" {
		t.Errorf("unexpected ID: %s", peering.GetID())
	}
}

func TestTransitGatewayAttachment_GetNextHops_Legacy(t *testing.T) {
	tgwClient := newMockAWSClient()
	tgwClient.transitGWs["tgw-123"] = &domain.TransitGatewayData{
		ID:      "tgw-123",
		OwnerID: "000000000000",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("000000000000", tgwClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tga := NewTransitGatewayAttachment(&domain.TGWAttachmentData{
		ID:               "tgw-attach-123",
		TransitGatewayID: "tgw-123",
		TGWAccountID:     "000000000000",
		VPCID:            "vpc-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}
	hops, err := tga.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	tgw, ok := hops[0].(*TransitGateway)
	if !ok {
		t.Fatalf("expected TransitGateway, got %T", hops[0])
	}

	if tgw.data.ID != "tgw-123" {
		t.Errorf("expected tgw-123, got %s", tgw.data.ID)
	}
}

func TestTransitGatewayAttachment_GetID(t *testing.T) {
	tga := NewTransitGatewayAttachment(&domain.TGWAttachmentData{ID: "tgw-attach-abc"}, "111111111111")

	if tga.GetID() != "111111111111:tgw-attach-abc" {
		t.Errorf("unexpected ID: %s", tga.GetID())
	}
}

func TestTransitGateway_GetNextHops_MatchingRoute(t *testing.T) {
	targetClient := newMockAWSClient()
	targetClient.tgwAttachments["tgw-attach-target"] = &domain.TGWAttachmentData{ID: "tgw-attach-target", TransitGatewayID: "tgw-123", TGWAccountID: "000000000000", VPCID: "vpc-target", SubnetIDs: []string{"subnet-target"}, State: "available"}
	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID: "tgw-123", OwnerID: "000000000000",
		RouteTables: []domain.TGWRouteTableData{{ID: "tgw-rtb-123", Routes: []domain.TGWRoute{{DestinationCIDR: "10.2.0.0/16", PrefixLength: 16, State: "active", Attachments: []domain.TGWRouteAttachment{{ID: "tgw-attach-target", Type: "vpc", ResourceID: "tgw-attach-target", OwnerID: "222222222222", State: "available"}}}}}},
	}, "000000000000", "")

	hops, err := tgw.GetNextHops(domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}, analyzerCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}
	if _, ok := hops[0].(*TransitGatewayVPCAttachmentInbound); !ok {
		t.Errorf("expected TransitGatewayVPCAttachmentInbound, got %T", hops[0])
	}
}

func TestTransitGateway_GetNextHops_NoMatchingRoute(t *testing.T) {
	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID: "tgw-123", OwnerID: "000000000000",
		RouteTables: []domain.TGWRouteTableData{{ID: "tgw-rtb-123", Routes: []domain.TGWRoute{{DestinationCIDR: "10.2.0.0/16", PrefixLength: 16, State: "active", Attachments: []domain.TGWRouteAttachment{{ID: "tgw-attach-target", Type: "vpc", ResourceID: "tgw-attach-target", OwnerID: "222222222222", State: "available"}}}}}},
	}, "000000000000", "")

	_, err := tgw.GetNextHops(domain.RoutingTarget{IP: "192.168.1.100", Port: 443, Protocol: "tcp"}, nil)
	if err == nil {
		t.Fatalf("expected error for no matching route")
	}
	var blockingError *domain.BlockingError
	if !errors.As(err, &blockingError) {
		t.Fatalf("expected BlockingError, got %T", err)
	}
}

func TestTransitGateway_GetNextHops_LongestPrefixMatch(t *testing.T) {
	targetClient := newMockAWSClient()
	targetClient.tgwAttachments["tgw-attach-specific"] = &domain.TGWAttachmentData{ID: "tgw-attach-specific", TransitGatewayID: "tgw-123", VPCID: "vpc-specific", State: "available"}
	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID: "tgw-123", OwnerID: "000000000000",
		RouteTables: []domain.TGWRouteTableData{{ID: "tgw-rtb-123", Routes: []domain.TGWRoute{
			{DestinationCIDR: "10.0.0.0/8", PrefixLength: 8, State: "active", Attachments: []domain.TGWRouteAttachment{{ID: "tgw-attach-general", Type: "vpc", ResourceID: "tgw-attach-general", OwnerID: "222222222222", State: "available"}}},
			{DestinationCIDR: "10.2.0.0/16", PrefixLength: 16, State: "active", Attachments: []domain.TGWRouteAttachment{{ID: "tgw-attach-specific", Type: "vpc", ResourceID: "tgw-attach-specific", OwnerID: "222222222222", State: "available"}}},
		}}},
	}, "000000000000", "")

	hops, err := tgw.GetNextHops(domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}, analyzerCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}
	if hops[0].(*TransitGatewayVPCAttachmentInbound).data.ID != "tgw-attach-specific" {
		t.Errorf("expected tgw-attach-specific (longer prefix)")
	}
}

func TestTransitGateway_GetID(t *testing.T) {
	tgw := NewTransitGateway(&domain.TransitGatewayData{ID: "tgw-abc"}, "000000000000", "")
	if tgw.GetID() != "000000000000:tgw-abc" {
		t.Errorf("unexpected ID: %s", tgw.GetID())
	}
}
func TestTransitGatewayVPCAttachmentInbound_GetNextHops_DestInSubnet(t *testing.T) {
	client := newMockAWSClient()
	client.subnets["subnet-123"] = &domain.SubnetData{
		ID:           "subnet-123",
		VPCID:        "vpc-123",
		CIDRBlock:    "10.2.1.0/24",
		RouteTableID: "rtb-123",
	}
	client.routeTables["rtb-123"] = &domain.RouteTableData{
		ID:    "rtb-123",
		VPCID: "vpc-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	inbound := NewTransitGatewayVPCAttachmentInbound(&domain.TGWAttachmentData{
		ID:        "tgw-attach-123",
		VPCID:     "vpc-123",
		SubnetIDs: []string{"subnet-123"},
	}, "222222222222")

	dest := domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}
	hops, err := inbound.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	rt, ok := hops[0].(*RouteTable)
	if !ok {
		t.Fatalf("expected RouteTable, got %T", hops[0])
	}

	if rt.data.ID != "rtb-123" {
		t.Errorf("expected rtb-123, got %s", rt.data.ID)
	}
}

func TestTransitGatewayVPCAttachmentInbound_GetNextHops_FallbackToMainRT(t *testing.T) {
	client := newMockAWSClient()
	client.subnets["subnet-123"] = &domain.SubnetData{
		ID:           "subnet-123",
		VPCID:        "vpc-123",
		CIDRBlock:    "10.2.1.0/24",
		RouteTableID: "rtb-subnet",
	}
	client.vpcs["vpc-123"] = &domain.VPCData{
		ID:               "vpc-123",
		CIDRBlock:        "10.2.0.0/16",
		MainRouteTableID: "rtb-main",
	}
	client.routeTables["rtb-main"] = &domain.RouteTableData{
		ID:    "rtb-main",
		VPCID: "vpc-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	inbound := NewTransitGatewayVPCAttachmentInbound(&domain.TGWAttachmentData{
		ID:        "tgw-attach-123",
		VPCID:     "vpc-123",
		SubnetIDs: []string{"subnet-123"},
	}, "222222222222")

	dest := domain.RoutingTarget{IP: "10.2.99.100", Port: 443, Protocol: "tcp"}
	hops, err := inbound.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	rt, ok := hops[0].(*RouteTable)
	if !ok {
		t.Fatalf("expected RouteTable, got %T", hops[0])
	}

	if rt.data.ID != "rtb-main" {
		t.Errorf("expected rtb-main (fallback), got %s", rt.data.ID)
	}
}

func TestTransitGatewayVPCAttachmentInbound_GetID(t *testing.T) {
	inbound := NewTransitGatewayVPCAttachmentInbound(&domain.TGWAttachmentData{ID: "tgw-attach-abc"}, "222222222222")

	expected := "222222222222:tgw-attach-abc:inbound"
	if inbound.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, inbound.GetID())
	}
}

func TestInternetGateway_GetRoutingTarget(t *testing.T) {
	igw := NewInternetGateway(&domain.InternetGatewayData{ID: "igw-123"}, "111111111111")

	target := igw.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("IGW should return empty routing target")
	}
}

func TestNATGateway_GetAccountID(t *testing.T) {
	nat := NewNATGateway(&domain.NATGatewayData{ID: "nat-123"}, "333333333333")

	if nat.GetAccountID() != "333333333333" {
		t.Errorf("unexpected account ID: %s", nat.GetAccountID())
	}
}

func TestNATGateway_GetRoutingTarget(t *testing.T) {
	nat := NewNATGateway(&domain.NATGatewayData{ID: "nat-123"}, "111111111111")

	target := nat.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("NAT should return empty routing target")
	}
}

func TestVPCEndpoint_GetAccountID(t *testing.T) {
	endpoint := NewVPCEndpoint(&domain.VPCEndpointData{ID: "vpce-123"}, "444444444444")

	if endpoint.GetAccountID() != "444444444444" {
		t.Errorf("unexpected account ID: %s", endpoint.GetAccountID())
	}
}

func TestVPCEndpoint_GetRoutingTarget(t *testing.T) {
	endpoint := NewVPCEndpoint(&domain.VPCEndpointData{ID: "vpce-123"}, "111111111111")

	target := endpoint.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("VPC endpoint should return empty routing target")
	}
}

func TestVPCPeering_GetAccountID(t *testing.T) {
	peering := NewVPCPeering(&domain.VPCPeeringData{ID: "pcx-123", RequesterOwner: "111111111111"}, "555555555555", "vpc-123")

	if peering.GetAccountID() != "555555555555" {
		t.Errorf("unexpected account ID: %s", peering.GetAccountID())
	}
}

func TestVPCPeering_GetRoutingTarget(t *testing.T) {
	peering := NewVPCPeering(&domain.VPCPeeringData{ID: "pcx-123", RequesterOwner: "111111111111"}, "111111111111", "vpc-123")

	target := peering.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("VPC peering should return empty routing target")
	}
}

func TestVPCPeering_GetNextHops_ClientNotFound(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	peering := NewVPCPeering(&domain.VPCPeeringData{
		ID:             "pcx-123",
		RequesterVPC:   "vpc-123",
		RequesterOwner: "111111111111",
		AccepterVPC:    "vpc-456",
		AccepterOwner:  "222222222222",
	}, "111111111111", "vpc-123")

	dest := domain.RoutingTarget{IP: "10.1.1.100", Port: 443, Protocol: "tcp"}
	_, err := peering.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for client not found")
	}
}

func TestVPCPeering_GetNextHops_VPCNotFound(t *testing.T) {
	accepterClient := newMockAWSClient()

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", accepterClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	peering := NewVPCPeering(&domain.VPCPeeringData{
		ID:             "pcx-123",
		RequesterVPC:   "vpc-123",
		RequesterOwner: "111111111111",
		AccepterVPC:    "vpc-456",
		AccepterOwner:  "222222222222",
	}, "111111111111", "vpc-123")

	dest := domain.RoutingTarget{IP: "10.1.1.100", Port: 443, Protocol: "tcp"}
	_, err := peering.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for VPC not found")
	}
}

func TestVPCPeering_GetNextHops_RouteTableNotFound(t *testing.T) {
	accepterClient := newMockAWSClient()
	accepterClient.vpcs["vpc-456"] = &domain.VPCData{
		ID:               "vpc-456",
		CIDRBlock:        "10.1.0.0/16",
		MainRouteTableID: "rtb-nonexistent",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", accepterClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	peering := NewVPCPeering(&domain.VPCPeeringData{
		ID:             "pcx-123",
		RequesterVPC:   "vpc-123",
		RequesterOwner: "111111111111",
		AccepterVPC:    "vpc-456",
		AccepterOwner:  "222222222222",
	}, "111111111111", "vpc-123")

	dest := domain.RoutingTarget{IP: "10.1.1.100", Port: 443, Protocol: "tcp"}
	_, err := peering.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for route table not found")
	}
}

func TestTransitGatewayAttachment_GetAccountID(t *testing.T) {
	tga := NewTransitGatewayAttachment(&domain.TGWAttachmentData{ID: "tgw-attach-123"}, "666666666666")

	if tga.GetAccountID() != "666666666666" {
		t.Errorf("unexpected account ID: %s", tga.GetAccountID())
	}
}

func TestTransitGatewayAttachment_GetRoutingTarget(t *testing.T) {
	tga := NewTransitGatewayAttachment(&domain.TGWAttachmentData{ID: "tgw-attach-123"}, "111111111111")

	target := tga.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("TGW attachment should return empty routing target")
	}
}

func TestTransitGatewayAttachment_GetNextHops_ClientNotFound(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tga := NewTransitGatewayAttachment(&domain.TGWAttachmentData{
		ID:               "tgw-attach-123",
		TransitGatewayID: "tgw-123",
		TGWAccountID:     "000000000000",
		VPCID:            "vpc-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}
	_, err := tga.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for client not found")
	}
}

func TestTransitGatewayAttachment_GetNextHops_TGWNotFound(t *testing.T) {
	tgwClient := newMockAWSClient()

	accountCtx := newMockAccountContext()
	accountCtx.addClient("000000000000", tgwClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tga := NewTransitGatewayAttachment(&domain.TGWAttachmentData{
		ID:               "tgw-attach-123",
		TransitGatewayID: "tgw-nonexistent",
		TGWAccountID:     "000000000000",
		VPCID:            "vpc-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}
	_, err := tga.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for TGW not found")
	}
}

func TestTransitGateway_GetAccountID(t *testing.T) {
	tgw := NewTransitGateway(&domain.TransitGatewayData{ID: "tgw-abc"}, "777777777777", "")

	if tgw.GetAccountID() != "777777777777" {
		t.Errorf("unexpected account ID: %s", tgw.GetAccountID())
	}
}

func TestTransitGateway_GetNextHops_MultipleRouteTables(t *testing.T) {
	targetClient := newMockAWSClient()
	targetClient.tgwAttachments["tgw-attach-rt2"] = &domain.TGWAttachmentData{
		ID:               "tgw-attach-rt2",
		TransitGatewayID: "tgw-123",
		VPCID:            "vpc-rt2",
		State:            "available",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID:      "tgw-123",
		OwnerID: "000000000000",
		RouteTables: []domain.TGWRouteTableData{
			{
				ID: "tgw-rtb-1",
				Routes: []domain.TGWRoute{
					{DestinationCIDR: "10.1.0.0/16", PrefixLength: 16, State: "active", Attachments: []domain.TGWRouteAttachment{{ID: "tgw-attach-rt1", Type: "vpc", ResourceID: "tgw-attach-rt1", OwnerID: "222222222222", State: "available"}}},
				},
			},
			{
				ID: "tgw-rtb-2",
				Routes: []domain.TGWRoute{
					{DestinationCIDR: "10.2.0.0/16", PrefixLength: 16, State: "active", Attachments: []domain.TGWRouteAttachment{{ID: "tgw-attach-rt2", Type: "vpc", ResourceID: "tgw-attach-rt2", OwnerID: "222222222222", State: "available"}}},
				},
			},
		},
	}, "000000000000", "")

	dest := domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}
	hops, err := tgw.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	inbound := hops[0].(*TransitGatewayVPCAttachmentInbound)
	if inbound.data.ID != "tgw-attach-rt2" {
		t.Errorf("expected tgw-attach-rt2, got %s", inbound.data.ID)
	}
}

func TestTransitGateway_GetNextHops_EmptyRouteTables(t *testing.T) {
	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID:          "tgw-123",
		OwnerID:     "000000000000",
		RouteTables: []domain.TGWRouteTableData{},
	}, "000000000000", "")

	dest := domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}
	_, err := tgw.GetNextHops(dest, nil)

	if err == nil {
		t.Fatal("expected error for empty route tables")
	}
}

func TestTransitGatewayVPCAttachmentInbound_GetAccountID(t *testing.T) {
	inbound := NewTransitGatewayVPCAttachmentInbound(&domain.TGWAttachmentData{ID: "tgw-attach-123"}, "888888888888")

	if inbound.GetAccountID() != "888888888888" {
		t.Errorf("unexpected account ID: %s", inbound.GetAccountID())
	}
}

func TestTransitGatewayVPCAttachmentInbound_GetRoutingTarget(t *testing.T) {
	inbound := NewTransitGatewayVPCAttachmentInbound(&domain.TGWAttachmentData{ID: "tgw-attach-123"}, "111111111111")

	target := inbound.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("TGW VPC attachment inbound should return empty routing target")
	}
}

func TestTransitGatewayVPCAttachmentInbound_GetNextHops_ClientNotFound(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	inbound := NewTransitGatewayVPCAttachmentInbound(&domain.TGWAttachmentData{
		ID:        "tgw-attach-123",
		VPCID:     "vpc-123",
		SubnetIDs: []string{"subnet-123"},
	}, "999999999999")

	dest := domain.RoutingTarget{IP: "10.2.1.100", Port: 443, Protocol: "tcp"}
	_, err := inbound.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for client not found")
	}
}

func TestTransitGatewayVPCAttachmentInbound_GetNextHops_VPCNotFound(t *testing.T) {
	client := newMockAWSClient()
	client.subnets["subnet-123"] = &domain.SubnetData{
		ID:        "subnet-123",
		CIDRBlock: "10.2.1.0/24",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	inbound := NewTransitGatewayVPCAttachmentInbound(&domain.TGWAttachmentData{
		ID:        "tgw-attach-123",
		VPCID:     "vpc-nonexistent",
		SubnetIDs: []string{"subnet-123"},
	}, "222222222222")

	dest := domain.RoutingTarget{IP: "10.2.99.100", Port: 443, Protocol: "tcp"}
	_, err := inbound.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for VPC not found")
	}
}

func TestTransitGatewayVPCAttachmentInbound_GetNextHops_MultipleSubnets(t *testing.T) {
	client := newMockAWSClient()
	client.subnets["subnet-1"] = &domain.SubnetData{
		ID:           "subnet-1",
		VPCID:        "vpc-123",
		CIDRBlock:    "10.2.1.0/24",
		RouteTableID: "rtb-1",
	}
	client.subnets["subnet-2"] = &domain.SubnetData{
		ID:           "subnet-2",
		VPCID:        "vpc-123",
		CIDRBlock:    "10.2.2.0/24",
		RouteTableID: "rtb-2",
	}
	client.routeTables["rtb-2"] = &domain.RouteTableData{
		ID:    "rtb-2",
		VPCID: "vpc-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	inbound := NewTransitGatewayVPCAttachmentInbound(&domain.TGWAttachmentData{
		ID:        "tgw-attach-123",
		VPCID:     "vpc-123",
		SubnetIDs: []string{"subnet-1", "subnet-2"},
	}, "222222222222")

	dest := domain.RoutingTarget{IP: "10.2.2.100", Port: 443, Protocol: "tcp"}
	hops, err := inbound.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	rt := hops[0].(*RouteTable)
	if rt.data.ID != "rtb-2" {
		t.Errorf("expected rtb-2, got %s", rt.data.ID)
	}
}

func TestVirtualPrivateGateway_GetNextHops_RoutesToVPN(t *testing.T) {
	targetClient := newMockAWSClient()
	targetClient.vpnConnections["vpn-123"] = &domain.VPNConnectionData{
		ID:          "vpn-123",
		VGWID:       "vgw-123",
		State:       "available",
		HasUpTunnel: true,
	}
	targetClient.vpnConnections["vpn-456"] = &domain.VPNConnectionData{
		ID:          "vpn-456",
		VGWID:       "vgw-123",
		State:       "available",
		HasUpTunnel: true,
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	vgw := NewVirtualPrivateGateway(&domain.VirtualPrivateGatewayData{
		ID:    "vgw-123",
		VPCID: "vpc-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "192.168.1.100", Port: 443, Protocol: "tcp"}
	hops, err := vgw.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 2 {
		t.Errorf("expected 2 VPN connections, got %d", len(hops))
	}
}

func TestVirtualPrivateGateway_GetNextHops_NoVPNConnections(t *testing.T) {
	targetClient := newMockAWSClient()

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	vgw := NewVirtualPrivateGateway(&domain.VirtualPrivateGatewayData{
		ID:    "vgw-123",
		VPCID: "vpc-123",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "192.168.1.100", Port: 443, Protocol: "tcp"}
	_, err := vgw.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error when no VPN connections attached")
	}

	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "no VPN connections attached to VGW" {
		t.Errorf("unexpected error reason: %s", blockingErr.Reason)
	}
}

func TestVirtualPrivateGateway_GetID(t *testing.T) {
	vgw := NewVirtualPrivateGateway(&domain.VirtualPrivateGatewayData{ID: "vgw-abc"}, "111111111111")

	if vgw.GetID() != "111111111111:vgw-abc" {
		t.Errorf("unexpected ID: %s", vgw.GetID())
	}
}

func TestVirtualPrivateGateway_GetAccountID(t *testing.T) {
	vgw := NewVirtualPrivateGateway(&domain.VirtualPrivateGatewayData{}, "222222222222")

	if vgw.GetAccountID() != "222222222222" {
		t.Errorf("unexpected account ID: %s", vgw.GetAccountID())
	}
}

func TestVirtualPrivateGateway_GetRoutingTarget(t *testing.T) {
	vgw := NewVirtualPrivateGateway(&domain.VirtualPrivateGatewayData{ID: "vgw-123"}, "111111111111")

	target := vgw.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("VGW should return empty routing target")
	}
}

func TestVPNConnection_GetNextHops(t *testing.T) {
	vpn := NewVPNConnection(&domain.VPNConnectionData{
		ID:          "vpn-123",
		VGWID:       "vgw-123",
		State:       "available",
		HasUpTunnel: true,
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "192.168.1.100", Port: 443, Protocol: "tcp"}
	hops, err := vpn.GetNextHops(dest, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}
}

func TestVPNConnection_GetID(t *testing.T) {
	vpn := NewVPNConnection(&domain.VPNConnectionData{ID: "vpn-abc"}, "111111111111")

	if vpn.GetID() != "111111111111:vpn-abc" {
		t.Errorf("unexpected ID: %s", vpn.GetID())
	}
}

func TestVPNConnection_GetAccountID(t *testing.T) {
	vpn := NewVPNConnection(&domain.VPNConnectionData{}, "333333333333")

	if vpn.GetAccountID() != "333333333333" {
		t.Errorf("unexpected account ID: %s", vpn.GetAccountID())
	}
}

func TestVPNConnection_GetRoutingTarget(t *testing.T) {
	vpn := NewVPNConnection(&domain.VPNConnectionData{ID: "vpn-123"}, "111111111111")

	target := vpn.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("VPN connection should return empty routing target")
	}
}

func TestDirectConnectGateway_GetNextHops(t *testing.T) {
	dxgw := NewDirectConnectGateway(&domain.DirectConnectGatewayData{
		ID:      "dxgw-123",
		OwnerID: "111111111111",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.100.1.100", Port: 443, Protocol: "tcp"}
	hops, err := dxgw.GetNextHops(dest, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}
}

func TestDirectConnectGateway_GetID(t *testing.T) {
	dxgw := NewDirectConnectGateway(&domain.DirectConnectGatewayData{ID: "dxgw-abc"}, "111111111111")

	if dxgw.GetID() != "111111111111:dxgw-abc" {
		t.Errorf("unexpected ID: %s", dxgw.GetID())
	}
}

func TestDirectConnectGateway_GetAccountID(t *testing.T) {
	dxgw := NewDirectConnectGateway(&domain.DirectConnectGatewayData{}, "444444444444")

	if dxgw.GetAccountID() != "444444444444" {
		t.Errorf("unexpected account ID: %s", dxgw.GetAccountID())
	}
}

func TestDirectConnectGateway_GetRoutingTarget(t *testing.T) {
	dxgw := NewDirectConnectGateway(&domain.DirectConnectGatewayData{ID: "dxgw-123"}, "111111111111")

	target := dxgw.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("Direct Connect Gateway should return empty routing target")
	}
}

func TestTGWPeeringAttachment_GetNextHops_Success(t *testing.T) {
	peerClient := newMockAWSClient()
	peerClient.transitGWs["tgw-peer"] = &domain.TransitGatewayData{
		ID:      "tgw-peer",
		OwnerID: "222222222222",
		RouteTables: []domain.TGWRouteTableData{
			{
				ID: "tgw-rtb-peer",
				Routes: []domain.TGWRoute{
					{
						DestinationCIDR: "10.0.0.0/8",
						PrefixLength:    8,
						State:           "active",
						Attachments: []domain.TGWRouteAttachment{
							{ID: "tgw-attach-vpc", Type: "vpc", ResourceID: "tgw-attach-vpc", OwnerID: "222222222222", State: "available"},
						},
					},
				},
			},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", peerClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	peering := NewTGWPeeringAttachment(&domain.TGWPeeringAttachmentData{
		ID:                   "tgw-attach-peering",
		TransitGatewayID:     "tgw-local",
		PeerTransitGatewayID: "tgw-peer",
		PeerAccountID:        "222222222222",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	hops, err := peering.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop (peer TGW), got %d", len(hops))
	}

	peerTGW, ok := hops[0].(*TransitGateway)
	if !ok {
		t.Fatalf("expected TransitGateway, got %T", hops[0])
	}

	if peerTGW.data.ID != "tgw-peer" {
		t.Errorf("expected tgw-peer, got %s", peerTGW.data.ID)
	}
}

func TestTGWPeeringAttachment_GetID(t *testing.T) {
	peering := NewTGWPeeringAttachment(&domain.TGWPeeringAttachmentData{ID: "tgw-attach-peer"}, "111111111111")

	if peering.GetID() != "111111111111:tgw-attach-peer" {
		t.Errorf("unexpected ID: %s", peering.GetID())
	}
}

func TestTGWPeeringAttachment_GetAccountID(t *testing.T) {
	peering := NewTGWPeeringAttachment(&domain.TGWPeeringAttachmentData{}, "555555555555")

	if peering.GetAccountID() != "555555555555" {
		t.Errorf("unexpected account ID: %s", peering.GetAccountID())
	}
}

func TestTGWPeeringAttachment_GetRoutingTarget(t *testing.T) {
	peering := NewTGWPeeringAttachment(&domain.TGWPeeringAttachmentData{ID: "tgw-attach-peer"}, "111111111111")

	target := peering.GetRoutingTarget()
	if target.IP != "" || target.Port != 0 || target.Protocol != "" {
		t.Error("TGW Peering Attachment should return empty routing target")
	}
}

func TestTGWPeeringAttachment_GetNextHops_PeerClientNotFound(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	peering := NewTGWPeeringAttachment(&domain.TGWPeeringAttachmentData{
		ID:                   "tgw-attach-peering",
		TransitGatewayID:     "tgw-local",
		PeerTransitGatewayID: "tgw-peer",
		PeerAccountID:        "999999999999",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	_, err := peering.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for peer client not found")
	}
}

func TestTGWPeeringAttachment_GetNextHops_PeerTGWNotFound(t *testing.T) {
	peerClient := newMockAWSClient()

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", peerClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	peering := NewTGWPeeringAttachment(&domain.TGWPeeringAttachmentData{
		ID:                   "tgw-attach-peering",
		TransitGatewayID:     "tgw-local",
		PeerTransitGatewayID: "tgw-nonexistent",
		PeerAccountID:        "222222222222",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	_, err := peering.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for peer TGW not found")
	}
}

func TestTransitGateway_GetNextHops_PeeringAttachmentType(t *testing.T) {
	targetClient := newMockAWSClient()
	targetClient.tgwPeerings["tgw-attach-peering"] = &domain.TGWPeeringAttachmentData{
		ID:                   "tgw-attach-peering",
		TransitGatewayID:     "tgw-local",
		PeerTransitGatewayID: "tgw-peer",
		PeerAccountID:        "333333333333",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID:      "tgw-123",
		OwnerID: "111111111111",
		RouteTables: []domain.TGWRouteTableData{
			{
				ID: "tgw-rtb-123",
				Routes: []domain.TGWRoute{
					{
						DestinationCIDR: "10.100.0.0/16",
						PrefixLength:    16,
						State:           "active",
						Attachments: []domain.TGWRouteAttachment{
							{
								ID:      "tgw-attach-peering",
								Type:    "peering",
								OwnerID: "222222222222",
								State:   "available",
							},
						},
					},
				},
			},
		},
	}, "111111111111", "")

	dest := domain.RoutingTarget{IP: "10.100.1.100", Port: 443, Protocol: "tcp"}
	hops, err := tgw.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	peering, ok := hops[0].(*TGWPeeringAttachment)
	if !ok {
		t.Fatalf("expected TGWPeeringAttachment, got %T", hops[0])
	}

	if peering.data.ID != "tgw-attach-peering" {
		t.Errorf("expected tgw-attach-peering, got %s", peering.data.ID)
	}
}

func TestTransitGateway_GetNextHops_VPNAttachmentType(t *testing.T) {
	targetClient := newMockAWSClient()
	targetClient.vpnConnections["vpn-123"] = &domain.VPNConnectionData{
		ID:          "vpn-123",
		VGWID:       "vgw-123",
		State:       "available",
		HasUpTunnel: true,
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID:      "tgw-123",
		OwnerID: "111111111111",
		RouteTables: []domain.TGWRouteTableData{
			{
				ID: "tgw-rtb-123",
				Routes: []domain.TGWRoute{
					{
						DestinationCIDR: "192.168.0.0/16",
						PrefixLength:    16,
						State:           "active",
						Attachments: []domain.TGWRouteAttachment{
							{
								ID:         "tgw-attach-vpn",
								Type:       "vpn",
								ResourceID: "vpn-123",
								OwnerID:    "222222222222",
								State:      "available",
							},
						},
					},
				},
			},
		},
	}, "111111111111", "")

	dest := domain.RoutingTarget{IP: "192.168.1.100", Port: 443, Protocol: "tcp"}
	hops, err := tgw.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	vpn, ok := hops[0].(*VPNConnection)
	if !ok {
		t.Fatalf("expected VPNConnection, got %T", hops[0])
	}

	if vpn.data.ID != "vpn-123" {
		t.Errorf("expected vpn-123, got %s", vpn.data.ID)
	}
}

func TestTransitGateway_GetNextHops_DirectConnectAttachmentType(t *testing.T) {
	targetClient := newMockAWSClient()
	targetClient.dxGateways["dxgw-123"] = &domain.DirectConnectGatewayData{
		ID:      "dxgw-123",
		OwnerID: "222222222222",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID:      "tgw-123",
		OwnerID: "111111111111",
		RouteTables: []domain.TGWRouteTableData{
			{
				ID: "tgw-rtb-123",
				Routes: []domain.TGWRoute{
					{
						DestinationCIDR: "172.16.0.0/12",
						PrefixLength:    12,
						State:           "active",
						Attachments: []domain.TGWRouteAttachment{
							{
								ID:         "tgw-attach-dxgw",
								Type:       "direct-connect-gateway",
								ResourceID: "dxgw-123",
								OwnerID:    "222222222222",
								State:      "available",
							},
						},
					},
				},
			},
		},
	}, "111111111111", "")

	dest := domain.RoutingTarget{IP: "172.16.1.100", Port: 443, Protocol: "tcp"}
	hops, err := tgw.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}

	dxgw, ok := hops[0].(*DirectConnectGateway)
	if !ok {
		t.Fatalf("expected DirectConnectGateway, got %T", hops[0])
	}

	if dxgw.data.ID != "dxgw-123" {
		t.Errorf("expected dxgw-123, got %s", dxgw.data.ID)
	}
}

func TestTransitGateway_GetNextHops_VPNAttachmentNotFound(t *testing.T) {
	targetClient := newMockAWSClient()

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID:      "tgw-123",
		OwnerID: "111111111111",
		RouteTables: []domain.TGWRouteTableData{
			{
				ID: "tgw-rtb-123",
				Routes: []domain.TGWRoute{
					{
						DestinationCIDR: "192.168.0.0/16",
						PrefixLength:    16,
						State:           "active",
						Attachments: []domain.TGWRouteAttachment{
							{
								ID:         "tgw-attach-vpn",
								Type:       "vpn",
								ResourceID: "vpn-nonexistent",
								OwnerID:    "222222222222",
								State:      "available",
							},
						},
					},
				},
			},
		},
	}, "111111111111", "")

	dest := domain.RoutingTarget{IP: "192.168.1.100", Port: 443, Protocol: "tcp"}
	_, err := tgw.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for VPN not found")
	}
}

func TestTransitGateway_GetNextHops_PeeringAttachmentNotFound(t *testing.T) {
	targetClient := newMockAWSClient()

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID:      "tgw-123",
		OwnerID: "111111111111",
		RouteTables: []domain.TGWRouteTableData{
			{
				ID: "tgw-rtb-123",
				Routes: []domain.TGWRoute{
					{
						DestinationCIDR: "10.100.0.0/16",
						PrefixLength:    16,
						State:           "active",
						Attachments: []domain.TGWRouteAttachment{
							{
								ID:      "peering-nonexistent",
								Type:    "peering",
								OwnerID: "222222222222",
								State:   "available",
							},
						},
					},
				},
			},
		},
	}, "111111111111", "")

	dest := domain.RoutingTarget{IP: "10.100.1.100", Port: 443, Protocol: "tcp"}
	_, err := tgw.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for peering attachment not found")
	}
}

func TestTransitGateway_GetNextHops_DirectConnectNotFound(t *testing.T) {
	targetClient := newMockAWSClient()

	accountCtx := newMockAccountContext()
	accountCtx.addClient("222222222222", targetClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tgw := NewTransitGateway(&domain.TransitGatewayData{
		ID:      "tgw-123",
		OwnerID: "111111111111",
		RouteTables: []domain.TGWRouteTableData{
			{
				ID: "tgw-rtb-123",
				Routes: []domain.TGWRoute{
					{
						DestinationCIDR: "172.16.0.0/12",
						PrefixLength:    12,
						State:           "active",
						Attachments: []domain.TGWRouteAttachment{
							{
								ID:         "tgw-attach-dxgw",
								Type:       "direct-connect-gateway",
								ResourceID: "dxgw-nonexistent",
								OwnerID:    "222222222222",
								State:      "available",
							},
						},
					},
				},
			},
		},
	}, "111111111111", "")

	dest := domain.RoutingTarget{IP: "172.16.1.100", Port: 443, Protocol: "tcp"}
	_, err := tgw.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for Direct Connect Gateway not found")
	}
}

func TestMultiTGW_TraversalPath(t *testing.T) {
	tgw1Client := newMockAWSClient()
	tgw1Client.tgwPeerings["tgw-attach-peer-1to2"] = &domain.TGWPeeringAttachmentData{
		ID:                   "tgw-attach-peer-1to2",
		TransitGatewayID:     "tgw-1",
		PeerTransitGatewayID: "tgw-2",
		PeerAccountID:        "222222222222",
	}

	tgw2Client := newMockAWSClient()
	tgw2Client.transitGWs["tgw-2"] = &domain.TransitGatewayData{
		ID:      "tgw-2",
		OwnerID: "222222222222",
		RouteTables: []domain.TGWRouteTableData{
			{
				ID: "tgw-rtb-2",
				Associations: []domain.TGWRouteTableAssociation{
					{
						AttachmentID: "tgw-attach-peer-1to2",
						ResourceType: "peering",
						State:        "associated",
					},
				},
				Routes: []domain.TGWRoute{
					{
						DestinationCIDR: "10.200.0.0/16",
						PrefixLength:    16,
						State:           "active",
						Attachments: []domain.TGWRouteAttachment{
							{
								ID:      "tgw-attach-vpc-dest",
								Type:    "vpc",
								OwnerID: "222222222222",
								State:   "available",
							},
						},
					},
				},
			},
		},
	}
	tgw2Client.tgwAttachments["tgw-attach-vpc-dest"] = &domain.TGWAttachmentData{
		ID:               "tgw-attach-vpc-dest",
		TransitGatewayID: "tgw-2",
		TGWAccountID:     "222222222222",
		VPCID:            "vpc-dest",
		SubnetIDs:        []string{"subnet-dest"},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", tgw1Client)
	accountCtx.addClient("222222222222", tgw2Client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tgw1 := NewTransitGateway(&domain.TransitGatewayData{
		ID:      "tgw-1",
		OwnerID: "111111111111",
		RouteTables: []domain.TGWRouteTableData{
			{
				ID: "tgw-rtb-1",
				Routes: []domain.TGWRoute{
					{
						DestinationCIDR: "10.200.0.0/16",
						PrefixLength:    16,
						State:           "active",
						Attachments: []domain.TGWRouteAttachment{
							{
								ID:      "tgw-attach-peer-1to2",
								Type:    "peering",
								OwnerID: "111111111111",
								State:   "available",
							},
						},
					},
				},
			},
		},
	}, "111111111111", "")

	dest := domain.RoutingTarget{IP: "10.200.1.100", Port: 443, Protocol: "tcp"}
	hops1, err := tgw1.GetNextHops(dest, analyzerCtx)
	if err != nil {
		t.Fatalf("TGW1 GetNextHops error: %v", err)
	}

	if len(hops1) != 1 {
		t.Fatalf("TGW1 expected 1 hop, got %d", len(hops1))
	}

	peering, ok := hops1[0].(*TGWPeeringAttachment)
	if !ok {
		t.Fatalf("expected TGWPeeringAttachment from TGW1, got %T", hops1[0])
	}

	hops2, err := peering.GetNextHops(dest, analyzerCtx)
	if err != nil {
		t.Fatalf("peering GetNextHops error: %v", err)
	}

	if len(hops2) != 1 {
		t.Fatalf("peering expected 1 hop, got %d", len(hops2))
	}

	tgw2, ok := hops2[0].(*TransitGateway)
	if !ok {
		t.Fatalf("expected TransitGateway from peering, got %T", hops2[0])
	}

	if tgw2.data.ID != "tgw-2" {
		t.Errorf("expected tgw-2, got %s", tgw2.data.ID)
	}

	hops3, err := tgw2.GetNextHops(dest, analyzerCtx)
	if err != nil {
		t.Fatalf("TGW2 GetNextHops error: %v", err)
	}

	if len(hops3) != 1 {
		t.Fatalf("TGW2 expected 1 hop, got %d", len(hops3))
	}

	_, ok = hops3[0].(*TransitGatewayVPCAttachmentInbound)
	if !ok {
		t.Fatalf("expected TransitGatewayVPCAttachmentInbound from TGW2, got %T", hops3[0])
	}
}
