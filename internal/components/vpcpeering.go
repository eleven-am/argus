package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type VPCPeering struct {
	data        *domain.VPCPeeringData
	accountID   string
	sourceVPCID string
}

func NewVPCPeering(data *domain.VPCPeeringData, accountID, sourceVPCID string) *VPCPeering {
	return &VPCPeering{
		data:        data,
		accountID:   accountID,
		sourceVPCID: sourceVPCID,
	}
}

func (vp *VPCPeering) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if vp.data.Status != "" && vp.data.Status != "active" {
		return nil, &domain.BlockingError{
			ComponentID: vp.GetID(),
			Reason:      fmt.Sprintf("vpc peering connection state is %s, not active", vp.data.Status),
		}
	}

	var targetVPCID string
	var targetAccountID string

	if vp.sourceVPCID == vp.data.RequesterVPC {
		targetVPCID = vp.data.AccepterVPC
		targetAccountID = vp.data.AccepterOwner
	} else {
		targetVPCID = vp.data.RequesterVPC
		targetAccountID = vp.data.RequesterOwner
	}

	client, err := analyzerCtx.GetAccountContext().GetClient(targetAccountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	vpcData, err := client.GetVPC(ctx, targetVPCID)
	if err != nil {
		return nil, err
	}

	rtData, err := client.GetRouteTable(ctx, vpcData.MainRouteTableID)
	if err != nil {
		return nil, err
	}

	return []domain.Component{NewRouteTable(rtData, targetAccountID)}, nil
}

func (vp *VPCPeering) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (vp *VPCPeering) GetID() string {
	return fmt.Sprintf("%s:%s", vp.accountID, vp.data.ID)
}

func (vp *VPCPeering) GetAccountID() string {
	return vp.accountID
}

func (vp *VPCPeering) GetComponentType() string {
	return "VPCPeering"
}
