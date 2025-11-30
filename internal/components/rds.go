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

	if len(r.data.SubnetIDs) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: r.GetID(),
			Reason:      "RDS instance missing subnet data",
		}
	}

	subnetData, err := client.GetSubnet(ctx, r.data.SubnetIDs[0])
	if err != nil {
		return nil, err
	}

	var next domain.Component = NewSubnet(subnetData, r.accountID)

	for i := len(r.data.SecurityGroups) - 1; i >= 0; i-- {
		sgData, err := client.GetSecurityGroup(ctx, r.data.SecurityGroups[i])
		if err != nil {
			return nil, err
		}
		next = NewSecurityGroupWithNext(sgData, r.accountID, next)
	}

	return []domain.Component{next}, nil
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

func (r *RDSInstance) GetComponentType() string {
	return "RDSInstance"
}

func (r *RDSInstance) GetVPCID() string {
	return ""
}

func (r *RDSInstance) GetRegion() string {
	return ""
}

func (r *RDSInstance) GetSubnetID() string {
	if len(r.data.SubnetIDs) > 0 {
		return r.data.SubnetIDs[0]
	}
	return ""
}

func (r *RDSInstance) GetAvailabilityZone() string {
	return ""
}
