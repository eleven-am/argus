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
	var components []domain.Component

	for _, sgID := range e.data.SecurityGroups {
		sgData, err := client.GetSecurityGroup(ctx, sgID)
		if err != nil {
			return nil, err
		}
		components = append(components, NewSecurityGroup(sgData, e.accountID))
	}

	if len(e.data.SubnetIDs) > 0 {
		subnetData, err := client.GetSubnet(ctx, e.data.SubnetIDs[0])
		if err != nil {
			return nil, err
		}
		components = append(components, NewSubnet(subnetData, e.accountID))
	}

	return components, nil
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
