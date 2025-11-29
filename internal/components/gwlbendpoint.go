package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type GWLBEndpoint struct {
	data      *domain.VPCEndpointData
	accountID string
}

func NewGWLBEndpoint(data *domain.VPCEndpointData, accountID string) *GWLBEndpoint {
	return &GWLBEndpoint{
		data:      data,
		accountID: accountID,
	}
}

func (ge *GWLBEndpoint) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if ge.data.State != "" && ge.data.State != "available" {
		return nil, &domain.BlockingError{
			ComponentID: ge.GetID(),
			Reason:      fmt.Sprintf("gwlb endpoint state is %s, not available", ge.data.State),
		}
	}

	if dest.IP == "" {
		return nil, &domain.BlockingError{
			ComponentID: ge.GetID(),
			Reason:      "gwlb endpoint requires a destination IP",
		}
	}

	if analyzerCtx == nil {
		return []domain.Component{NewIPTarget(&domain.IPTargetData{IP: dest.IP, Port: dest.Port}, ge.accountID)}, nil
	}

	client, err := analyzerCtx.GetAccountContext().GetClient(ge.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	if len(ge.data.SubnetIDs) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: ge.GetID(),
			Reason:      "gwlb endpoint missing subnet associations",
		}
	}

	var components []domain.Component
	for _, subnetID := range ge.data.SubnetIDs {
		subnetData, err := client.GetSubnet(ctx, subnetID)
		if err != nil {
			continue
		}
		subnet := NewSubnet(subnetData, ge.accountID)

		var terminal domain.Component = subnet
		for i := len(ge.data.SecurityGroups) - 1; i >= 0; i-- {
			sgData, err := client.GetSecurityGroup(ctx, ge.data.SecurityGroups[i])
			if err != nil {
				terminal = nil
				break
			}
			terminal = NewSecurityGroupWithNext(sgData, ge.accountID, terminal)
		}

		if terminal != nil {
			components = append(components, terminal)
		}
	}

	if len(components) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: ge.GetID(),
			Reason:      "no accessible subnets/security groups for gwlb endpoint",
		}
	}

	return components, nil
}

func (ge *GWLBEndpoint) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (ge *GWLBEndpoint) GetID() string {
	return fmt.Sprintf("%s:%s", ge.accountID, ge.data.ID)
}

func (ge *GWLBEndpoint) GetAccountID() string {
	return ge.accountID
}
