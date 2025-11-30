package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type CLB struct {
	data      *domain.CLBData
	accountID string
}

func NewCLB(data *domain.CLBData, accountID string) *CLB {
	return &CLB{
		data:      data,
		accountID: accountID,
	}
}

func (clb *CLB) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(clb.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	var sgDatas []*domain.SecurityGroupData
	for _, sgID := range clb.data.SecurityGroups {
		sgData, err := client.GetSecurityGroup(ctx, sgID)
		if err != nil {
			return nil, err
		}
		sgDatas = append(sgDatas, sgData)
	}

	var targets []domain.Component
	for _, instanceID := range clb.data.InstanceIDs {
		instance, err := client.GetEC2Instance(ctx, instanceID)
		if err != nil {
			return nil, err
		}
		targets = append(targets, NewEC2Instance(instance, clb.accountID))
	}

	if len(targets) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: clb.GetID(),
			Reason:      "no instances registered with CLB",
		}
	}

	if len(sgDatas) == 0 {
		return targets, nil
	}

	var components []domain.Component
	for _, target := range targets {
		var next domain.Component = target
		for i := len(sgDatas) - 1; i >= 0; i-- {
			next = NewSecurityGroupWithNext(sgDatas[i], clb.accountID, next)
		}
		components = append(components, next)
	}

	return components, nil
}

func (clb *CLB) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (clb *CLB) GetID() string {
	return fmt.Sprintf("%s:clb:%s", clb.accountID, clb.data.Name)
}

func (clb *CLB) GetAccountID() string {
	return clb.accountID
}

func (clb *CLB) GetComponentType() string {
	return "CLB"
}

func (clb *CLB) GetVPCID() string {
	return clb.data.VPCID
}

func (clb *CLB) GetRegion() string {
	return ""
}

func (clb *CLB) GetSubnetID() string {
	if len(clb.data.SubnetIDs) > 0 {
		return clb.data.SubnetIDs[0]
	}
	return ""
}

func (clb *CLB) GetAvailabilityZone() string {
	return ""
}
