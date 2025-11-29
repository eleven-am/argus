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

	for _, sgID := range nlb.data.SecurityGroups {
		sgData, err := client.GetSecurityGroup(ctx, sgID)
		if err != nil {
			return nil, err
		}
		sg := NewSecurityGroup(sgData, nlb.accountID)
		_, err = sg.GetNextHops(dest, analyzerCtx)
		if err != nil {
			return nil, &domain.BlockingError{
				ComponentID: nlb.GetID(),
				Reason:      fmt.Sprintf("NLB security group %s blocked: %v", sgID, err),
			}
		}
	}

	var components []domain.Component
	for _, tgARN := range nlb.data.TargetGroupARNs {
		tgData, err := client.GetTargetGroup(ctx, tgARN)
		if err != nil {
			return nil, err
		}
		components = append(components, NewTargetGroup(tgData, nlb.accountID))
	}

	if len(components) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: nlb.GetID(),
			Reason:      "no target groups configured for NLB",
		}
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
