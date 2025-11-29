package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type RDSInstance struct {
	data      *domain.RDSInstanceData
	accountID string
}

func NewRDSInstance(data *domain.RDSInstanceData, accountID string) *RDSInstance {
	return &RDSInstance{
		data:      data,
		accountID: accountID,
	}
}

func (r *RDSInstance) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(r.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	var components []domain.Component

	for _, sgID := range r.data.SecurityGroups {
		sgData, err := client.GetSecurityGroup(ctx, sgID)
		if err != nil {
			return nil, err
		}
		components = append(components, NewSecurityGroup(sgData, r.accountID))
	}

	if len(r.data.SubnetIDs) > 0 {
		subnetData, err := client.GetSubnet(ctx, r.data.SubnetIDs[0])
		if err != nil {
			return nil, err
		}
		components = append(components, NewSubnet(subnetData, r.accountID))
	}

	return components, nil
}

func (r *RDSInstance) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{
		IP:       r.data.PrivateIP,
		Port:     r.data.Port,
		Protocol: "tcp",
	}
}

func (r *RDSInstance) GetID() string {
	return fmt.Sprintf("%s:%s", r.accountID, r.data.ID)
}

func (r *RDSInstance) GetAccountID() string {
	return r.accountID
}
