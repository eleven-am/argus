package components

import (
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestEKSPod_GetID(t *testing.T) {
	pod := NewEKSPod(&domain.EKSPodData{
		PodIP:          "10.0.1.50",
		HostIP:         "10.0.1.10",
		ENIID:          "eni-12345",
		SecurityGroups: []string{"sg-123"},
		SubnetID:       "subnet-123",
	}, "123456789012")

	expected := "123456789012:eks-pod:10.0.1.50"
	if pod.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, pod.GetID())
	}
}

func TestEKSPod_GetAccountID(t *testing.T) {
	pod := NewEKSPod(&domain.EKSPodData{
		PodIP: "10.0.1.50",
	}, "123456789012")

	if pod.GetAccountID() != "123456789012" {
		t.Errorf("expected account ID 123456789012, got %s", pod.GetAccountID())
	}
}

func TestEKSPod_GetRoutingTarget(t *testing.T) {
	pod := NewEKSPod(&domain.EKSPodData{
		PodIP: "10.0.1.50",
	}, "123456789012")

	target := pod.GetRoutingTarget()

	if target.IP != "10.0.1.50" {
		t.Errorf("expected IP 10.0.1.50, got %s", target.IP)
	}
	if target.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", target.Protocol)
	}
}

func TestEKSPod_GetNextHops(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.securityGroups["sg-123"] = &domain.SecurityGroupData{
		ID:    "sg-123",
		VPCID: "vpc-123",
	}
	mockClient.subnets["subnet-123"] = &domain.SubnetData{
		ID:           "subnet-123",
		VPCID:        "vpc-123",
		CIDRBlock:    "10.0.1.0/24",
		RouteTableID: "rtb-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	pod := NewEKSPod(&domain.EKSPodData{
		PodIP:          "10.0.1.50",
		SecurityGroups: []string{"sg-123"},
		SubnetID:       "subnet-123",
	}, "123456789012")

	hops, err := pod.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected single chained hop head, got %d", len(hops))
	}
}
