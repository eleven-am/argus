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

	if e.data.SubnetID == "" {
		return nil, &domain.BlockingError{
			ComponentID: e.GetID(),
			Reason:      "EKS pod missing subnet data",
		}
	}

	subnetData, err := client.GetSubnet(ctx, e.data.SubnetID)
	if err != nil {
		return nil, err
	}

	var next domain.Component = NewSubnet(subnetData, e.accountID)

	for i := len(e.data.SecurityGroups) - 1; i >= 0; i-- {
		sgData, err := client.GetSecurityGroup(ctx, e.data.SecurityGroups[i])
		if err != nil {
			return nil, err
		}
		next = NewSecurityGroupWithNext(sgData, e.accountID, next)
	}

	return []domain.Component{next}, nil
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

func (e *EKSPod) GetComponentType() string {
	return "EKSPod"
}

func (e *EKSPod) GetVPCID() string {
	return ""
}

func (e *EKSPod) GetRegion() string {
	return ""
}

func (e *EKSPod) GetSubnetID() string {
	return e.data.SubnetID
}

func (e *EKSPod) GetAvailabilityZone() string {
	return ""
}
