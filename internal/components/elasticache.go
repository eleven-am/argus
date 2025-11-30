package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type ElastiCacheCluster struct {
	data      *domain.ElastiCacheClusterData
	accountID string
}

func NewElastiCacheCluster(data *domain.ElastiCacheClusterData, accountID string) *ElastiCacheCluster {
	return &ElastiCacheCluster{
		data:      data,
		accountID: accountID,
	}
}

func (e *ElastiCacheCluster) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(e.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	if len(e.data.SubnetIDs) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: e.GetID(),
			Reason:      "ElastiCache cluster missing subnet data",
		}
	}

	subnetData, err := client.GetSubnet(ctx, e.data.SubnetIDs[0])
	if err != nil {
		return nil, err
	}

	var next domain.Component = NewSubnet(subnetData, e.accountID)

	for i := len(e.data.SecurityGroups) - 1; i >= 0; i-- {
		sgData, err := client.GetSecurityGroup(ctx, e.data.SecurityGroups[i])
		if err != nil {
			return nil, err
		}
		next = NewSecurityGroupWithNext(sgData, e.accountID, next)
	}

	return []domain.Component{next}, nil
}

func (e *ElastiCacheCluster) GetRoutingTarget() domain.RoutingTarget {
	ip := ""
	port := e.data.Port

	if len(e.data.Nodes) > 0 {
		ip = e.data.Nodes[0].PrivateIP
		if ip == "" {
			ip = e.data.Nodes[0].Endpoint
		}
		if e.data.Nodes[0].Port != 0 {
			port = e.data.Nodes[0].Port
		}
	}

	if port == 0 {
		switch e.data.Engine {
		case "redis":
			port = 6379
		case "memcached":
			port = 11211
		default:
			port = 6379
		}
	}

	return domain.RoutingTarget{
		IP:       ip,
		Port:     port,
		Protocol: "tcp",
	}
}

func (e *ElastiCacheCluster) GetID() string {
	return fmt.Sprintf("%s:elasticache:%s", e.accountID, e.data.ID)
}

func (e *ElastiCacheCluster) GetAccountID() string {
	return e.accountID
}

func (e *ElastiCacheCluster) GetComponentType() string {
	return "ElastiCacheCluster"
}

func (e *ElastiCacheCluster) GetVPCID() string {
	return e.data.VPCID
}

func (e *ElastiCacheCluster) GetRegion() string {
	return ""
}

func (e *ElastiCacheCluster) GetSubnetID() string {
	if len(e.data.SubnetIDs) > 0 {
		return e.data.SubnetIDs[0]
	}
	return ""
}

func (e *ElastiCacheCluster) GetAvailabilityZone() string {
	return ""
}
