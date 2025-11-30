package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type NLB struct {
	data      *domain.NLBData
	accountID string
}

func NewNLB(data *domain.NLBData, accountID string) *NLB {
	return &NLB{
		data:      data,
		accountID: accountID,
	}
}

func (nlb *NLB) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(nlb.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	var sgDatas []*domain.SecurityGroupData
	for _, sgID := range nlb.data.SecurityGroups {
		sgData, err := client.GetSecurityGroup(ctx, sgID)
		if err != nil {
			return nil, err
		}
		sgDatas = append(sgDatas, sgData)
	}

	var targets []domain.Component
	for _, tgARN := range nlb.data.TargetGroupARNs {
		tgData, err := client.GetTargetGroup(ctx, tgARN)
		if err != nil {
			return nil, err
		}
		targets = append(targets, NewTargetGroup(tgData, nlb.accountID))
	}

	if len(targets) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: nlb.GetID(),
			Reason:      "no target groups configured for NLB",
		}
	}

	if len(sgDatas) == 0 {
		return targets, nil
	}

	var components []domain.Component
	for _, target := range targets {
		var next domain.Component = target
		for i := len(sgDatas) - 1; i >= 0; i-- {
			next = NewSecurityGroupWithNext(sgDatas[i], nlb.accountID, next)
		}
		components = append(components, next)
	}

	return components, nil
}

func (nlb *NLB) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (nlb *NLB) GetID() string {
	return fmt.Sprintf("%s:%s", nlb.accountID, nlb.data.ARN)
}

func (nlb *NLB) GetAccountID() string {
	return nlb.accountID
}

func (nlb *NLB) GetComponentType() string {
	return "NLB"
}

func (nlb *NLB) GetVPCID() string {
	return nlb.data.VPCID
}

func (nlb *NLB) GetRegion() string {
	return ""
}

func (nlb *NLB) GetSubnetID() string {
	if len(nlb.data.SubnetIDs) > 0 {
		return nlb.data.SubnetIDs[0]
	}
	return ""
}

func (nlb *NLB) GetAvailabilityZone() string {
	return ""
}
