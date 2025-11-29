package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type GWLB struct {
	data      *domain.GWLBData
	accountID string
}

func NewGWLB(data *domain.GWLBData, accountID string) *GWLB {
	return &GWLB{
		data:      data,
		accountID: accountID,
	}
}

func (gwlb *GWLB) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(gwlb.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	var components []domain.Component

	for _, tgARN := range gwlb.data.TargetGroupARNs {
		tgData, err := client.GetTargetGroup(ctx, tgARN)
		if err != nil {
			return nil, err
		}
		components = append(components, NewTargetGroup(tgData, gwlb.accountID))
	}

	if len(components) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: gwlb.GetID(),
			Reason:      "no target groups configured for GWLB",
		}
	}

	return components, nil
}

func (gwlb *GWLB) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (gwlb *GWLB) GetID() string {
	return fmt.Sprintf("%s:%s", gwlb.accountID, gwlb.data.ARN)
}

func (gwlb *GWLB) GetAccountID() string {
	return gwlb.accountID
}
