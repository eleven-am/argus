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

	for _, sgID := range clb.data.SecurityGroups {
		sgData, err := client.GetSecurityGroup(ctx, sgID)
		if err != nil {
			return nil, err
		}
		sg := NewSecurityGroup(sgData, clb.accountID)
		_, err = sg.GetNextHops(dest, analyzerCtx)
		if err != nil {
			return nil, &domain.BlockingError{
				ComponentID: clb.GetID(),
				Reason:      fmt.Sprintf("CLB security group %s blocked: %v", sgID, err),
			}
		}
	}

	var components []domain.Component
	for _, instanceID := range clb.data.InstanceIDs {
		instance, err := client.GetEC2Instance(ctx, instanceID)
		if err != nil {
			return nil, err
		}
		components = append(components, NewEC2Instance(instance, clb.accountID))
	}

	if len(components) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: clb.GetID(),
			Reason:      "no instances registered with CLB",
		}
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
