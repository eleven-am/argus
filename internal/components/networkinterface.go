package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type NetworkInterface struct {
	id        string
	accountID string
	privateIP string
}

func NewNetworkInterface(id, accountID string) *NetworkInterface {
	return &NetworkInterface{
		id:        id,
		accountID: accountID,
	}
}

func (eni *NetworkInterface) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(eni.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	eniData, err := client.GetNetworkInterface(ctx, eni.id)
	if err != nil {
		return nil, err
	}
	eni.privateIP = eniData.PrivateIP

	subnetData, err := client.GetSubnet(ctx, eniData.SubnetID)
	if err != nil {
		return nil, err
	}
	subnet := NewSubnet(subnetData, eni.accountID)

	var terminal domain.Component = subnet
	for i := len(eniData.SecurityGroups) - 1; i >= 0; i-- {
		sgData, err := client.GetSecurityGroup(ctx, eniData.SecurityGroups[i])
		if err != nil {
			return nil, err
		}
		terminal = NewSecurityGroupWithNext(sgData, eni.accountID, terminal)
	}

	return []domain.Component{terminal}, nil
}

func (eni *NetworkInterface) GetRoutingTarget() domain.RoutingTarget {
	if eni.privateIP == "" {
		return domain.RoutingTarget{}
	}
	return domain.RoutingTarget{IP: eni.privateIP}
}

func (eni *NetworkInterface) GetID() string {
	return fmt.Sprintf("%s:%s", eni.accountID, eni.id)
}

func (eni *NetworkInterface) GetAccountID() string {
	return eni.accountID
}
