package components

import (
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestElastiCacheCluster_GetID(t *testing.T) {
	cluster := NewElastiCacheCluster(&domain.ElastiCacheClusterData{
		ID:     "my-redis-cluster",
		Engine: "redis",
	}, "123456789012")

	expected := "123456789012:elasticache:my-redis-cluster"
	if cluster.GetID() != expected {
		t.Errorf("expected %s, got %s", expected, cluster.GetID())
	}
}

func TestElastiCacheCluster_GetAccountID(t *testing.T) {
	cluster := NewElastiCacheCluster(&domain.ElastiCacheClusterData{
		ID: "my-redis-cluster",
	}, "123456789012")

	if cluster.GetAccountID() != "123456789012" {
		t.Errorf("expected account ID 123456789012, got %s", cluster.GetAccountID())
	}
}

func TestElastiCacheCluster_GetRoutingTarget_Redis(t *testing.T) {
	cluster := NewElastiCacheCluster(&domain.ElastiCacheClusterData{
		ID:     "my-redis-cluster",
		Engine: "redis",
		Nodes: []domain.ElastiCacheNodeData{
			{PrivateIP: "10.0.1.100", Port: 6379},
		},
	}, "123456789012")

	target := cluster.GetRoutingTarget()

	if target.IP != "10.0.1.100" {
		t.Errorf("expected IP 10.0.1.100, got %s", target.IP)
	}
	if target.Port != 6379 {
		t.Errorf("expected port 6379, got %d", target.Port)
	}
	if target.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", target.Protocol)
	}
}

func TestElastiCacheCluster_GetRoutingTarget_Memcached(t *testing.T) {
	cluster := NewElastiCacheCluster(&domain.ElastiCacheClusterData{
		ID:     "my-memcached-cluster",
		Engine: "memcached",
		Nodes: []domain.ElastiCacheNodeData{
			{PrivateIP: "10.0.1.101"},
		},
	}, "123456789012")

	target := cluster.GetRoutingTarget()

	if target.IP != "10.0.1.101" {
		t.Errorf("expected IP 10.0.1.101, got %s", target.IP)
	}
	if target.Port != 11211 {
		t.Errorf("expected port 11211, got %d", target.Port)
	}
}

func TestElastiCacheCluster_GetRoutingTarget_DefaultRedisPort(t *testing.T) {
	cluster := NewElastiCacheCluster(&domain.ElastiCacheClusterData{
		ID:     "my-cluster",
		Engine: "redis",
		Nodes: []domain.ElastiCacheNodeData{
			{PrivateIP: "10.0.1.100"},
		},
	}, "123456789012")

	target := cluster.GetRoutingTarget()

	if target.Port != 6379 {
		t.Errorf("expected default redis port 6379, got %d", target.Port)
	}
}

func TestElastiCacheCluster_GetNextHops(t *testing.T) {
	mockClient := newMockAWSClient()
	mockClient.securityGroups["sg-elasticache"] = &domain.SecurityGroupData{
		ID:    "sg-elasticache",
		VPCID: "vpc-123",
	}
	mockClient.subnets["subnet-elasticache"] = &domain.SubnetData{
		ID:           "subnet-elasticache",
		VPCID:        "vpc-123",
		CIDRBlock:    "10.0.1.0/24",
		RouteTableID: "rtb-123",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("123456789012", mockClient)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	cluster := NewElastiCacheCluster(&domain.ElastiCacheClusterData{
		ID:             "my-redis-cluster",
		Engine:         "redis",
		SecurityGroups: []string{"sg-elasticache"},
		SubnetIDs:      []string{"subnet-elasticache"},
		Nodes: []domain.ElastiCacheNodeData{
			{PrivateIP: "10.0.1.100", Port: 6379},
		},
	}, "123456789012")

	hops, err := cluster.GetNextHops(domain.RoutingTarget{}, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 2 {
		t.Errorf("expected 2 hops (SG + Subnet), got %d", len(hops))
	}
}
