package components

import (
	"errors"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestAPIGateway_GetNextHops_Edge(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:           "abc123",
		Name:         "my-api",
		APIType:      "REST",
		EndpointType: "EDGE",
	}, "123456789012")

	hops, err := apigw.GetNextHops(domain.RoutingTarget{}, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected 0 hops for EDGE endpoint (terminal), got %d", len(hops))
	}
}

func TestAPIGateway_GetNextHops_Regional_NoVPCLinks(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:           "abc123",
		Name:         "my-regional-api",
		APIType:      "REST",
		EndpointType: "REGIONAL",
		VPCLinkIDs:   []string{},
	}, "123456789012")

	hops, err := apigw.GetNextHops(domain.RoutingTarget{}, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected 0 hops for REGIONAL endpoint without VPC links (terminal), got %d", len(hops))
	}
}

func TestAPIGateway_GetNextHops_Private_NoVPCEndpoints(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:             "abc123",
		Name:           "my-private-api",
		APIType:        "REST",
		EndpointType:   "PRIVATE",
		VPCEndpointIDs: []string{},
	}, "123456789012")

	_, err := apigw.GetNextHops(domain.RoutingTarget{}, nil)

	if err == nil {
		t.Fatal("expected error for private API with no VPC endpoints")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "private API has no VPC endpoints configured" {
		t.Errorf("unexpected reason: %s", blockingErr.Reason)
	}
}

func TestAPIGateway_GetID(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:   "abc123",
		Name: "my-api",
	}, "123456789012")

	expected := "123456789012:apigw:abc123"
	if apigw.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, apigw.GetID())
	}
}

func TestAPIGateway_GetAccountID(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:   "abc123",
		Name: "my-api",
	}, "123456789012")

	if apigw.GetAccountID() != "123456789012" {
		t.Errorf("expected account ID 123456789012, got %s", apigw.GetAccountID())
	}
}

func TestAPIGateway_GetRoutingTarget_WithPrivateIPs(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:         "abc123",
		Name:       "my-api",
		PrivateIPs: []string{"10.0.1.100", "10.0.1.101"},
	}, "123456789012")

	target := apigw.GetRoutingTarget()

	if target.IP != "10.0.1.100" {
		t.Errorf("expected IP 10.0.1.100, got %s", target.IP)
	}
	if target.Port != 443 {
		t.Errorf("expected port 443, got %d", target.Port)
	}
	if target.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", target.Protocol)
	}
}

func TestAPIGateway_GetRoutingTarget_NoPrivateIPs(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:   "abc123",
		Name: "my-api",
	}, "123456789012")

	target := apigw.GetRoutingTarget()

	if target.IP != "" {
		t.Errorf("expected empty IP, got %s", target.IP)
	}
	if target.Port != 443 {
		t.Errorf("expected port 443, got %d", target.Port)
	}
}

func TestAPIGateway_IsTerminal_Edge(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:           "abc123",
		EndpointType: "EDGE",
	}, "123456789012")

	if !apigw.IsTerminal() {
		t.Error("expected EDGE API Gateway to be terminal")
	}
}

func TestAPIGateway_IsTerminal_Regional_NoVPCLinks(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:           "abc123",
		EndpointType: "REGIONAL",
		VPCLinkIDs:   []string{},
	}, "123456789012")

	if !apigw.IsTerminal() {
		t.Error("expected REGIONAL API Gateway without VPC links to be terminal")
	}
}

func TestAPIGateway_IsTerminal_Regional_WithVPCLinks(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:           "abc123",
		EndpointType: "REGIONAL",
		VPCLinkIDs:   []string{"vpcl-123"},
	}, "123456789012")

	if apigw.IsTerminal() {
		t.Error("expected REGIONAL API Gateway with VPC links to NOT be terminal")
	}
}

func TestAPIGateway_IsTerminal_Private(t *testing.T) {
	apigw := NewAPIGateway(&domain.APIGatewayData{
		ID:             "abc123",
		EndpointType:   "PRIVATE",
		VPCEndpointIDs: []string{"vpce-123"},
	}, "123456789012")

	if apigw.IsTerminal() {
		t.Error("expected PRIVATE API Gateway to NOT be terminal")
	}
}

func TestVPCLink_GetNextHops_V1_NoTargets(t *testing.T) {
	mockClient := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	vpcLink := NewVPCLink(&domain.VPCLinkData{
		ID:         "vpcl-123",
		Name:       "my-vpc-link",
		Version:    "V1",
		TargetARNs: []string{},
		Status:     "AVAILABLE",
	}, "123456789012")

	_, err := vpcLink.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for VPC link v1 with no NLB targets")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "no accessible NLB targets for VPC link v1" {
		t.Errorf("unexpected reason: %s", blockingErr.Reason)
	}
}

func TestVPCLink_GetNextHops_V2_NoSubnets(t *testing.T) {
	mockClient := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	vpcLink := NewVPCLink(&domain.VPCLinkData{
		ID:        "vpcl-123",
		Name:      "my-vpc-link-v2",
		Version:   "V2",
		SubnetIDs: []string{},
		Status:    "AVAILABLE",
	}, "123456789012")

	_, err := vpcLink.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for VPC link v2 with no subnets")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "VPC link v2 has no subnets configured" {
		t.Errorf("unexpected reason: %s", blockingErr.Reason)
	}
}

func TestVPCLink_GetNextHops_UnavailableStatus(t *testing.T) {
	mockClient := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	vpcLink := NewVPCLink(&domain.VPCLinkData{
		ID:      "vpcl-123",
		Name:    "my-vpc-link",
		Version: "V1",
		Status:  "PENDING",
	}, "123456789012")

	_, err := vpcLink.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for VPC link with PENDING status")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "VPC link status is PENDING, not AVAILABLE" {
		t.Errorf("unexpected reason: %s", blockingErr.Reason)
	}
}

func TestVPCLink_GetNextHops_UnknownVersion(t *testing.T) {
	mockClient := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	vpcLink := NewVPCLink(&domain.VPCLinkData{
		ID:      "vpcl-123",
		Name:    "my-vpc-link",
		Version: "V3",
		Status:  "AVAILABLE",
	}, "123456789012")

	_, err := vpcLink.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for unknown VPC link version")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "unknown VPC link version: V3" {
		t.Errorf("unexpected reason: %s", blockingErr.Reason)
	}
}

func TestVPCLink_GetID(t *testing.T) {
	vpcLink := NewVPCLink(&domain.VPCLinkData{
		ID:   "vpcl-abc123",
		Name: "my-vpc-link",
	}, "123456789012")

	expected := "123456789012:vpclink:vpcl-abc123"
	if vpcLink.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, vpcLink.GetID())
	}
}

func TestVPCLink_GetAccountID(t *testing.T) {
	vpcLink := NewVPCLink(&domain.VPCLinkData{
		ID:   "vpcl-abc123",
		Name: "my-vpc-link",
	}, "123456789012")

	if vpcLink.GetAccountID() != "123456789012" {
		t.Errorf("expected account ID 123456789012, got %s", vpcLink.GetAccountID())
	}
}

func TestVPCLink_GetRoutingTarget(t *testing.T) {
	vpcLink := NewVPCLink(&domain.VPCLinkData{
		ID:   "vpcl-abc123",
		Name: "my-vpc-link",
	}, "123456789012")

	target := vpcLink.GetRoutingTarget()

	if target.IP != "" || target.Port != 0 {
		t.Error("expected empty routing target for VPC link")
	}
}

func TestVPCLink_GetNextHops_V2_WithNLBTarget(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.nlbs["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/abc123"] = &domain.NLBData{
		ARN:   "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/abc123",
		VPCID: "vpc-123",
	}
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	vpcLink := NewVPCLink(&domain.VPCLinkData{
		ID:        "vpcl-123",
		Name:      "my-vpc-link-v2",
		Version:   "V2",
		SubnetIDs: []string{"subnet-123"},
		Status:    "AVAILABLE",
		IntegrationTargets: []string{
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/abc123",
		},
	}, "123456789012")

	hops, err := vpcLink.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (NLB), got %d", len(hops))
	}
}

func TestVPCLink_GetNextHops_V2_WithALBTarget(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.albs["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123"] = &domain.ALBData{
		ARN:   "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123",
		VPCID: "vpc-123",
	}
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	vpcLink := NewVPCLink(&domain.VPCLinkData{
		ID:        "vpcl-123",
		Name:      "my-vpc-link-v2",
		Version:   "V2",
		SubnetIDs: []string{"subnet-123"},
		Status:    "AVAILABLE",
		IntegrationTargets: []string{
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123",
		},
	}, "123456789012")

	hops, err := vpcLink.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (ALB), got %d", len(hops))
	}
}

func TestVPCLink_GetNextHops_V2_FallbackToSubnet(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.subnets["subnet-123"] = &domain.SubnetData{
		ID:           "subnet-123",
		VPCID:        "vpc-123",
		CIDRBlock:    "10.0.1.0/24",
		RouteTableID: "rtb-123",
	}
	mockClient.securityGroups["sg-123"] = &domain.SecurityGroupData{
		ID:    "sg-123",
		VPCID: "vpc-123",
	}
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	vpcLink := NewVPCLink(&domain.VPCLinkData{
		ID:             "vpcl-123",
		Name:           "my-vpc-link-v2",
		Version:        "V2",
		SubnetIDs:      []string{"subnet-123"},
		SecurityGroups: []string{"sg-123"},
		Status:         "AVAILABLE",
	}, "123456789012")

	hops, err := vpcLink.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (SG chain with subnet), got %d", len(hops))
	}
}

func TestExtractNLBARNFromTarget(t *testing.T) {
	tests := []struct {
		target   string
		expected string
	}{
		{
			target:   "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/abc123",
			expected: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/abc123",
		},
		{
			target:   "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123",
			expected: "",
		},
		{
			target:   "http://my-nlb.elb.amazonaws.com:80/api",
			expected: "",
		},
	}

	for _, tt := range tests {
		result := extractNLBARNFromTarget(tt.target)
		if result != tt.expected {
			t.Errorf("extractNLBARNFromTarget(%s) = %s, expected %s", tt.target, result, tt.expected)
		}
	}
}

func TestExtractALBARNFromTarget(t *testing.T) {
	tests := []struct {
		target   string
		expected string
	}{
		{
			target:   "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123",
			expected: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123",
		},
		{
			target:   "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/abc123",
			expected: "",
		},
		{
			target:   "http://my-alb.elb.amazonaws.com:443/api",
			expected: "",
		},
	}

	for _, tt := range tests {
		result := extractALBARNFromTarget(tt.target)
		if result != tt.expected {
			t.Errorf("extractALBARNFromTarget(%s) = %s, expected %s", tt.target, result, tt.expected)
		}
	}
}
