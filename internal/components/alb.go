package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type ALB struct {
	data      *domain.ALBData
	accountID string
}

func NewALB(data *domain.ALBData, accountID string) *ALB {
	return &ALB{
		data:      data,
		accountID: accountID,
	}
}

func (alb *ALB) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(alb.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	for _, sgID := range alb.data.SecurityGroups {
		sgData, err := client.GetSecurityGroup(ctx, sgID)
		if err != nil {
			return nil, err
		}
		sg := NewSecurityGroup(sgData, alb.accountID)
		_, err = sg.GetNextHops(dest, analyzerCtx)
		if err != nil {
			return nil, &domain.BlockingError{
				ComponentID: alb.GetID(),
				Reason:      fmt.Sprintf("ALB security group %s blocked: %v", sgID, err),
			}
		}
	}

	var components []domain.Component
	for _, tgARN := range alb.data.TargetGroupARNs {
		tgData, err := client.GetTargetGroup(ctx, tgARN)
		if err != nil {
			return nil, err
		}
		components = append(components, NewTargetGroup(tgData, alb.accountID))
	}

	if len(components) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: alb.GetID(),
			Reason:      "no target groups configured for ALB",
		}
	}

	return components, nil
}

func (alb *ALB) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (alb *ALB) GetID() string {
	return fmt.Sprintf("%s:%s", alb.accountID, alb.data.ARN)
}

func (alb *ALB) GetAccountID() string {
	return alb.accountID
}

func (alb *ALB) GetComponentType() string {
	return "ALB"
}

func (alb *ALB) GetVPCID() string {
	return alb.data.VPCID
}

func (alb *ALB) GetRegion() string {
	return ""
}

func (alb *ALB) GetSubnetID() string {
	if len(alb.data.SubnetIDs) > 0 {
		return alb.data.SubnetIDs[0]
	}
	return ""
}

func (alb *ALB) GetAvailabilityZone() string {
	return ""
}
