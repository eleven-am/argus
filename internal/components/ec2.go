package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type EC2Instance struct {
	data      *domain.EC2InstanceData
	accountID string
}

func NewEC2Instance(data *domain.EC2InstanceData, accountID string) *EC2Instance {
	return &EC2Instance{
		data:      data,
		accountID: accountID,
	}
}

func (e *EC2Instance) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(e.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	subnetData, err := client.GetSubnet(ctx, e.data.SubnetID)
	if err != nil {
		return nil, err
	}
	subnet := NewSubnet(subnetData, e.accountID)

	var terminal domain.Component = subnet
	for i := len(e.data.SecurityGroups) - 1; i >= 0; i-- {
		sgData, err := client.GetSecurityGroup(ctx, e.data.SecurityGroups[i])
		if err != nil {
			return nil, err
		}
		terminal = NewSecurityGroupWithNext(sgData, e.accountID, terminal)
	}

	return []domain.Component{terminal}, nil
}

func (e *EC2Instance) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{
		IP:       e.data.PrivateIP,
		Port:     0,
		Protocol: "tcp",
	}
}

func (e *EC2Instance) GetID() string {
	return fmt.Sprintf("%s:%s", e.accountID, e.data.ID)
}

func (e *EC2Instance) GetAccountID() string {
	return e.accountID
}
