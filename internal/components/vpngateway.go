package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type VirtualPrivateGateway struct {
	data      *domain.VirtualPrivateGatewayData
	accountID string
}

func NewVirtualPrivateGateway(data *domain.VirtualPrivateGatewayData, accountID string) *VirtualPrivateGateway {
	return &VirtualPrivateGateway{
		data:      data,
		accountID: accountID,
	}
}

func (vgw *VirtualPrivateGateway) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(vgw.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	vpnConns, err := client.GetVPNConnectionsByVGW(ctx, vgw.data.ID)
	if err != nil {
		return nil, err
	}

	var components []domain.Component
	for _, vpn := range vpnConns {
		components = append(components, NewVPNConnection(vpn, vgw.accountID))
	}

	if len(components) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: vgw.GetID(),
			Reason:      "no VPN connections attached to VGW",
		}
	}

	return components, nil
}

func (vgw *VirtualPrivateGateway) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (vgw *VirtualPrivateGateway) GetID() string {
	return fmt.Sprintf("%s:%s", vgw.accountID, vgw.data.ID)
}

func (vgw *VirtualPrivateGateway) GetAccountID() string {
	return vgw.accountID
}
