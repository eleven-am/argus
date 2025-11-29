package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type EKSPod struct {
	data      *domain.EKSPodData
	accountID string
}

func NewEKSPod(data *domain.EKSPodData, accountID string) *EKSPod {
	return &EKSPod{
		data:      data,
		accountID: accountID,
	}
}

func (e *EKSPod) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(e.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	var components []domain.Component

	for _, sgID := range e.data.SecurityGroups {
		sgData, err := client.GetSecurityGroup(ctx, sgID)
		if err != nil {
			return nil, err
		}
		components = append(components, NewSecurityGroup(sgData, e.accountID))
	}

	if e.data.SubnetID != "" {
		subnetData, err := client.GetSubnet(ctx, e.data.SubnetID)
		if err != nil {
			return nil, err
		}
		components = append(components, NewSubnet(subnetData, e.accountID))
	}

	return components, nil
}

func (e *EKSPod) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{
		IP:       e.data.PodIP,
		Protocol: "tcp",
	}
}

func (e *EKSPod) GetID() string {
	return fmt.Sprintf("%s:eks-pod:%s", e.accountID, e.data.PodIP)
}

func (e *EKSPod) GetAccountID() string {
	return e.accountID
}
