package components

import (
	"errors"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestIPTarget_GetNextHops(t *testing.T) {
	ipTarget := NewIPTarget(&domain.IPTargetData{
		IP:   "10.0.1.100",
		Port: 8080,
	}, "123456789012")

	hops, err := ipTarget.GetNextHops(domain.RoutingTarget{}, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 0 {
		t.Errorf("expected 0 hops, got %d", len(hops))
	}
}

func TestIPTarget_GetRoutingTarget(t *testing.T) {
	ipTarget := NewIPTarget(&domain.IPTargetData{
		IP:   "10.0.1.100",
		Port: 8080,
	}, "123456789012")

	target := ipTarget.GetRoutingTarget()

	if target.IP != "10.0.1.100" {
		t.Errorf("expected IP 10.0.1.100, got %s", target.IP)
	}
	if target.Port != 8080 {
		t.Errorf("expected Port 8080, got %d", target.Port)
	}
}

func TestIPTarget_GetID(t *testing.T) {
	ipTarget := NewIPTarget(&domain.IPTargetData{
		IP:   "10.0.1.100",
		Port: 8080,
	}, "123456789012")

	id := ipTarget.GetID()

	expected := "123456789012:ip:10.0.1.100:8080"
	if id != expected {
		t.Errorf("expected ID %s, got %s", expected, id)
	}
}

func TestTargetGroup_GetNextHops_InstanceTargets(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.ec2Instances["i-12345"] = &domain.EC2InstanceData{
		ID:             "i-12345",
		PrivateIP:      "10.0.1.10",
		SecurityGroups: []string{"sg-123"},
		SubnetID:       "subnet-123",
	}
	mockClient.ec2Instances["i-67890"] = &domain.EC2InstanceData{
		ID:             "i-67890",
		PrivateIP:      "10.0.1.11",
		SecurityGroups: []string{"sg-123"},
		SubnetID:       "subnet-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tg := NewTargetGroup(&domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123",
		Name:       "tg-1",
		TargetType: "instance",
		Protocol:   "HTTP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "i-12345", Port: 80, HealthStatus: "healthy"},
			{ID: "i-67890", Port: 80, HealthStatus: "healthy"},
		},
	}, "123456789012")

	hops, err := tg.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 2 {
		t.Errorf("expected 2 hops, got %d", len(hops))
	}
	for _, hop := range hops {
		if _, ok := hop.(*EC2Instance); !ok {
			t.Errorf("expected EC2Instance component, got %T", hop)
		}
	}
}

func TestTargetGroup_GetNextHops_IPTargets(t *testing.T) {
	mockClient := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tg := NewTargetGroup(&domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-ip/abc123",
		Name:       "tg-ip",
		TargetType: "ip",
		Protocol:   "HTTP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "10.0.1.100", Port: 8080, HealthStatus: "healthy"},
			{ID: "10.0.1.101", Port: 8080, HealthStatus: "healthy"},
		},
	}, "123456789012")

	hops, err := tg.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 2 {
		t.Errorf("expected 2 hops, got %d", len(hops))
	}
	for _, hop := range hops {
		if _, ok := hop.(*IPTarget); !ok {
			t.Errorf("expected IPTarget component, got %T", hop)
		}
	}
}

func TestTargetGroup_GetNextHops_LambdaTargets(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.lambdaFunctions["my-function"] = &domain.LambdaFunctionData{
		Name:           "my-function",
		VPCID:          "vpc-123",
		SubnetIDs:      []string{"subnet-123"},
		SecurityGroups: []string{"sg-123"},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tg := NewTargetGroup(&domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-lambda/abc123",
		Name:       "tg-lambda",
		TargetType: "lambda",
		Protocol:   "HTTP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "my-function", Port: 0, HealthStatus: "healthy"},
		},
	}, "123456789012")

	hops, err := tg.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop, got %d", len(hops))
	}
	if _, ok := hops[0].(*LambdaFunction); !ok {
		t.Errorf("expected LambdaFunction component, got %T", hops[0])
	}
}

func TestTargetGroup_GetNextHops_ALBTargets(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.albs["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-backend/abc123"] = &domain.ALBData{
		ARN:             "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-backend/abc123",
		DNSName:         "alb-backend.elb.amazonaws.com",
		Scheme:          "internal",
		VPCID:           "vpc-123",
		SubnetIDs:       []string{"subnet-123"},
		SecurityGroups:  []string{"sg-123"},
		TargetGroupARNs: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-backend/xyz789"},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tg := NewTargetGroup(&domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-nlb-alb/abc123",
		Name:       "tg-nlb-alb",
		TargetType: "alb",
		Protocol:   "TCP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-backend/abc123", Port: 80, HealthStatus: "healthy"},
		},
	}, "123456789012")

	hops, err := tg.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop, got %d", len(hops))
	}
	if _, ok := hops[0].(*ALB); !ok {
		t.Errorf("expected ALB component, got %T", hops[0])
	}
}

func TestTargetGroup_GetNextHops_NoHealthyTargets(t *testing.T) {
	mockClient := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tg := NewTargetGroup(&domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-unhealthy/abc123",
		Name:       "tg-unhealthy",
		TargetType: "instance",
		Protocol:   "HTTP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "i-12345", Port: 80, HealthStatus: "unhealthy"},
			{ID: "i-67890", Port: 80, HealthStatus: "draining"},
		},
	}, "123456789012")

	_, err := tg.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for no healthy targets")
	}
	blockingErr, ok := err.(*domain.BlockingError)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "no reachable targets in target group (all unhealthy or draining)" {
		t.Errorf("unexpected reason: %s", blockingErr.Reason)
	}
}

func TestTargetGroup_GetNextHops_InitialStatusAccepted(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.ec2Instances["i-initial"] = &domain.EC2InstanceData{
		ID:             "i-initial",
		PrivateIP:      "10.0.1.10",
		SecurityGroups: []string{"sg-123"},
		SubnetID:       "subnet-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tg := NewTargetGroup(&domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-initial/abc123",
		Name:       "tg-initial",
		TargetType: "instance",
		Protocol:   "HTTP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "i-initial", Port: 80, HealthStatus: "healthy"},
		},
	}, "123456789012")

	hops, err := tg.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (initial status should be reachable), got %d", len(hops))
	}
}

func TestTargetGroup_GetNextHops_OnlyHealthyTargetsReturned(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.ec2Instances["i-healthy"] = &domain.EC2InstanceData{
		ID:             "i-healthy",
		PrivateIP:      "10.0.1.10",
		SecurityGroups: []string{"sg-123"},
		SubnetID:       "subnet-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	tg := NewTargetGroup(&domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-mixed/abc123",
		Name:       "tg-mixed",
		TargetType: "instance",
		Protocol:   "HTTP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "i-healthy", Port: 80, HealthStatus: "healthy"},
			{ID: "i-unhealthy", Port: 80, HealthStatus: "unhealthy"},
		},
	}, "123456789012")

	hops, err := tg.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (only healthy), got %d", len(hops))
	}
}

func TestNLB_GetNextHops(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.targetGroups["arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"] = &domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123",
		Name:       "tg-1",
		TargetType: "ip",
		Protocol:   "TCP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "10.0.1.100", Port: 80, HealthStatus: "healthy"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	nlb := NewNLB(&domain.NLBData{
		ARN:             "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/nlb-1/abc123",
		DNSName:         "nlb-1.elb.amazonaws.com",
		Scheme:          "internal",
		VPCID:           "vpc-123",
		SubnetIDs:       []string{"subnet-123"},
		SecurityGroups:  []string{},
		TargetGroupARNs: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"},
	}, "123456789012")

	hops, err := nlb.GetNextHops(domain.RoutingTarget{IP: "10.0.1.100", Port: 80}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (target group), got %d", len(hops))
	}
	if _, ok := hops[0].(*TargetGroup); !ok {
		t.Errorf("expected TargetGroup component, got %T", hops[0])
	}
}

func TestNLB_GetNextHops_WithSecurityGroups(t *testing.T) {
	mockClient := newMockAWSClient()
	allowAllRule := domain.SecurityGroupRule{Protocol: "-1", CIDRBlocks: []string{"0.0.0.0/0"}}
	mockClient.securityGroups["sg-nlb"] = &domain.SecurityGroupData{
		ID:            "sg-nlb",
		VPCID:         "vpc-123",
		OutboundRules: []domain.SecurityGroupRule{allowAllRule},
		InboundRules:  []domain.SecurityGroupRule{allowAllRule},
	}
	mockClient.targetGroups["arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"] = &domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123",
		Name:       "tg-1",
		TargetType: "ip",
		Protocol:   "TCP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "10.0.1.100", Port: 80, HealthStatus: "healthy"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	nlb := NewNLB(&domain.NLBData{
		ARN:             "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/nlb-sg/abc123",
		DNSName:         "nlb-sg.elb.amazonaws.com",
		Scheme:          "internal",
		VPCID:           "vpc-123",
		SubnetIDs:       []string{"subnet-123"},
		SecurityGroups:  []string{"sg-nlb"},
		TargetGroupARNs: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"},
	}, "123456789012")

	hops, err := nlb.GetNextHops(domain.RoutingTarget{IP: "10.0.1.100", Port: 80}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (target group only, SGs evaluated internally), got %d", len(hops))
	}
}

func TestNLB_GetNextHops_SecurityGroupBlocks(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.securityGroups["sg-nlb-restrictive"] = &domain.SecurityGroupData{
		ID:    "sg-nlb-restrictive",
		VPCID: "vpc-123",
		OutboundRules: []domain.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlocks: []string{"10.0.0.0/8"}},
		},
	}
	mockClient.targetGroups["arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"] = &domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123",
		Name:       "tg-1",
		TargetType: "ip",
		Protocol:   "TCP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "10.0.1.100", Port: 80, HealthStatus: "healthy"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	nlb := NewNLB(&domain.NLBData{
		ARN:             "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/nlb-blocked/abc123",
		DNSName:         "nlb-blocked.elb.amazonaws.com",
		Scheme:          "internal",
		VPCID:           "vpc-123",
		SubnetIDs:       []string{"subnet-123"},
		SecurityGroups:  []string{"sg-nlb-restrictive"},
		TargetGroupARNs: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"},
	}, "123456789012")

	_, err := nlb.GetNextHops(domain.RoutingTarget{IP: "10.0.1.100", Port: 80}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error when SG blocks traffic")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.ComponentID == "" {
		t.Error("expected non-empty component ID")
	}
}

func TestNLB_GetNextHops_NoTargetGroups(t *testing.T) {
	mockClient := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	nlb := NewNLB(&domain.NLBData{
		ARN:             "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/nlb-empty/abc123",
		DNSName:         "nlb-empty.elb.amazonaws.com",
		Scheme:          "internal",
		VPCID:           "vpc-123",
		SubnetIDs:       []string{"subnet-123"},
		TargetGroupARNs: []string{},
	}, "123456789012")

	_, err := nlb.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for no target groups")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "no target groups configured for NLB" {
		t.Errorf("unexpected reason: %s", blockingErr.Reason)
	}
}

func TestALB_GetNextHops_SecurityGroupsEvaluatedThenTargetGroups(t *testing.T) {
	mockClient := newMockAWSClient()
	allowAllRule := domain.SecurityGroupRule{Protocol: "-1", CIDRBlocks: []string{"0.0.0.0/0"}}
	mockClient.securityGroups["sg-123"] = &domain.SecurityGroupData{
		ID:            "sg-123",
		VPCID:         "vpc-123",
		OutboundRules: []domain.SecurityGroupRule{allowAllRule},
		InboundRules:  []domain.SecurityGroupRule{allowAllRule},
	}
	mockClient.securityGroups["sg-456"] = &domain.SecurityGroupData{
		ID:            "sg-456",
		VPCID:         "vpc-123",
		OutboundRules: []domain.SecurityGroupRule{allowAllRule},
		InboundRules:  []domain.SecurityGroupRule{allowAllRule},
	}
	mockClient.targetGroups["arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"] = &domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123",
		Name:       "tg-1",
		TargetType: "instance",
		Protocol:   "HTTP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "i-12345", Port: 80, HealthStatus: "healthy"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	alb := NewALB(&domain.ALBData{
		ARN:             "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-1/abc123",
		DNSName:         "alb-1.elb.amazonaws.com",
		Scheme:          "internet-facing",
		VPCID:           "vpc-123",
		SubnetIDs:       []string{"subnet-123", "subnet-456"},
		SecurityGroups:  []string{"sg-123", "sg-456"},
		TargetGroupARNs: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"},
	}, "123456789012")

	hops, err := alb.GetNextHops(domain.RoutingTarget{IP: "10.0.1.100", Port: 80}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (TG only, SGs evaluated internally), got %d", len(hops))
	}
	if _, ok := hops[0].(*TargetGroup); !ok {
		t.Errorf("expected TargetGroup component, got %T", hops[0])
	}
}

func TestALB_GetNextHops_SecurityGroupBlocks(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.securityGroups["sg-restrictive"] = &domain.SecurityGroupData{
		ID:    "sg-restrictive",
		VPCID: "vpc-123",
		OutboundRules: []domain.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlocks: []string{"10.0.0.0/8"}},
		},
	}
	mockClient.targetGroups["arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"] = &domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123",
		Name:       "tg-1",
		TargetType: "instance",
		Protocol:   "HTTP",
		Port:       80,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "i-12345", Port: 80, HealthStatus: "healthy"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	alb := NewALB(&domain.ALBData{
		ARN:             "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-blocked/abc123",
		DNSName:         "alb-blocked.elb.amazonaws.com",
		Scheme:          "internet-facing",
		VPCID:           "vpc-123",
		SubnetIDs:       []string{"subnet-123"},
		SecurityGroups:  []string{"sg-restrictive"},
		TargetGroupARNs: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"},
	}, "123456789012")

	_, err := alb.GetNextHops(domain.RoutingTarget{IP: "10.0.1.100", Port: 80}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error when SG blocks traffic")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.ComponentID == "" {
		t.Error("expected non-empty component ID")
	}
}

func TestCLB_GetNextHops_SecurityGroupsEvaluatedThenInstances(t *testing.T) {
	mockClient := newMockAWSClient()
	allowAllRule := domain.SecurityGroupRule{Protocol: "-1", CIDRBlocks: []string{"0.0.0.0/0"}}
	mockClient.securityGroups["sg-clb"] = &domain.SecurityGroupData{
		ID:            "sg-clb",
		VPCID:         "vpc-123",
		OutboundRules: []domain.SecurityGroupRule{allowAllRule},
		InboundRules:  []domain.SecurityGroupRule{allowAllRule},
	}
	mockClient.ec2Instances["i-clb-1"] = &domain.EC2InstanceData{
		ID:             "i-clb-1",
		PrivateIP:      "10.0.1.10",
		SecurityGroups: []string{"sg-backend"},
		SubnetID:       "subnet-123",
	}
	mockClient.ec2Instances["i-clb-2"] = &domain.EC2InstanceData{
		ID:             "i-clb-2",
		PrivateIP:      "10.0.1.11",
		SecurityGroups: []string{"sg-backend"},
		SubnetID:       "subnet-456",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	clb := NewCLB(&domain.CLBData{
		Name:           "my-classic-lb",
		DNSName:        "my-classic-lb.elb.amazonaws.com",
		Scheme:         "internal",
		VPCID:          "vpc-123",
		SubnetIDs:      []string{"subnet-123", "subnet-456"},
		SecurityGroups: []string{"sg-clb"},
		InstanceIDs:    []string{"i-clb-1", "i-clb-2"},
	}, "123456789012")

	hops, err := clb.GetNextHops(domain.RoutingTarget{IP: "10.0.1.10", Port: 80}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 2 {
		t.Errorf("expected 2 hops (instances only, SGs evaluated internally), got %d", len(hops))
	}

	for _, hop := range hops {
		if _, ok := hop.(*EC2Instance); !ok {
			t.Errorf("expected EC2Instance component, got %T", hop)
		}
	}
}

func TestCLB_GetNextHops_SecurityGroupBlocks(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.securityGroups["sg-clb-restrictive"] = &domain.SecurityGroupData{
		ID:    "sg-clb-restrictive",
		VPCID: "vpc-123",
		OutboundRules: []domain.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlocks: []string{"192.168.0.0/16"}},
		},
	}
	mockClient.ec2Instances["i-clb-1"] = &domain.EC2InstanceData{
		ID:             "i-clb-1",
		PrivateIP:      "10.0.1.10",
		SecurityGroups: []string{"sg-backend"},
		SubnetID:       "subnet-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	clb := NewCLB(&domain.CLBData{
		Name:           "clb-blocked",
		DNSName:        "clb-blocked.elb.amazonaws.com",
		Scheme:         "internal",
		VPCID:          "vpc-123",
		SubnetIDs:      []string{"subnet-123"},
		SecurityGroups: []string{"sg-clb-restrictive"},
		InstanceIDs:    []string{"i-clb-1"},
	}, "123456789012")

	_, err := clb.GetNextHops(domain.RoutingTarget{IP: "10.0.1.10", Port: 80}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error when SG blocks traffic")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.ComponentID == "" {
		t.Error("expected non-empty component ID")
	}
}

func TestCLB_GetNextHops_NoInstances(t *testing.T) {
	mockClient := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	clb := NewCLB(&domain.CLBData{
		Name:           "empty-clb",
		DNSName:        "empty-clb.elb.amazonaws.com",
		Scheme:         "internal",
		VPCID:          "vpc-123",
		SubnetIDs:      []string{},
		SecurityGroups: []string{},
		InstanceIDs:    []string{},
	}, "123456789012")

	_, err := clb.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for empty CLB")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "no instances registered with CLB" {
		t.Errorf("unexpected reason: %s", blockingErr.Reason)
	}
}

func TestGWLB_GetNextHops(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.targetGroups["arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-appliance/abc123"] = &domain.TargetGroupData{
		ARN:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-appliance/abc123",
		Name:       "tg-appliance",
		TargetType: "ip",
		Protocol:   "GENEVE",
		Port:       6081,
		VPCID:      "vpc-123",
		Targets: []domain.TargetData{
			{ID: "10.0.1.50", Port: 6081, HealthStatus: "healthy"},
		},
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	gwlb := NewGWLB(&domain.GWLBData{
		ARN:             "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/gwy/gwlb-1/abc123",
		DNSName:         "gwlb-1.elb.amazonaws.com",
		VPCID:           "vpc-123",
		SubnetIDs:       []string{"subnet-123"},
		TargetGroupARNs: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-appliance/abc123"},
	}, "123456789012")

	hops, err := gwlb.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (target group), got %d", len(hops))
	}
	if _, ok := hops[0].(*TargetGroup); !ok {
		t.Errorf("expected TargetGroup component, got %T", hops[0])
	}
}

func TestGWLB_GetNextHops_NoTargetGroups(t *testing.T) {
	mockClient := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	gwlb := NewGWLB(&domain.GWLBData{
		ARN:             "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/gwy/gwlb-empty/abc123",
		DNSName:         "gwlb-empty.elb.amazonaws.com",
		VPCID:           "vpc-123",
		SubnetIDs:       []string{"subnet-123"},
		TargetGroupARNs: []string{},
	}, "123456789012")

	_, err := gwlb.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for no target groups")
	}
	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "no target groups configured for GWLB" {
		t.Errorf("unexpected reason: %s", blockingErr.Reason)
	}
}

func TestALB_GetID(t *testing.T) {
	alb := NewALB(&domain.ALBData{
		ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-1/abc123",
	}, "123456789012")

	expected := "123456789012:arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-1/abc123"
	if alb.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, alb.GetID())
	}
}

func TestNLB_GetID(t *testing.T) {
	nlb := NewNLB(&domain.NLBData{
		ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/nlb-1/abc123",
	}, "123456789012")

	expected := "123456789012:arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/nlb-1/abc123"
	if nlb.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, nlb.GetID())
	}
}

func TestGWLB_GetID(t *testing.T) {
	gwlb := NewGWLB(&domain.GWLBData{
		ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/gwy/gwlb-1/abc123",
	}, "123456789012")

	expected := "123456789012:arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/gwy/gwlb-1/abc123"
	if gwlb.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, gwlb.GetID())
	}
}

func TestCLB_GetID(t *testing.T) {
	clb := NewCLB(&domain.CLBData{
		Name: "my-classic-lb",
	}, "123456789012")

	expected := "123456789012:clb:my-classic-lb"
	if clb.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, clb.GetID())
	}
}

func TestTargetGroup_GetID(t *testing.T) {
	tg := NewTargetGroup(&domain.TargetGroupData{
		ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123",
	}, "123456789012")

	expected := "123456789012:arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-1/abc123"
	if tg.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, tg.GetID())
	}
}
