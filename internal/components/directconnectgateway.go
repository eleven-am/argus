package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type DirectConnectGateway struct {
	data      *domain.DirectConnectGatewayData
	accountID string
}

func NewDirectConnectGateway(data *domain.DirectConnectGatewayData, accountID string) *DirectConnectGateway {
	return &DirectConnectGateway{
		data:      data,
		accountID: accountID,
	}
}

func (dxgw *DirectConnectGateway) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if dest.IP == "" {
		return nil, &domain.BlockingError{
			ComponentID: dxgw.GetID(),
			Reason:      "direct connect gateway requires a destination IP to evaluate",
		}
	}

	if dxgw.data.State != "" && dxgw.data.State != "available" {
		return nil, &domain.BlockingError{
			ComponentID: dxgw.GetID(),
			Reason:      fmt.Sprintf("direct connect gateway state is %s, not available", dxgw.data.State),
		}
	}

	if len(dxgw.data.AllowedPrefixes) > 0 {
		allowed := false
		for _, prefix := range dxgw.data.AllowedPrefixes {
			if IPMatchesCIDR(dest.IP, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, &domain.BlockingError{
				ComponentID: dxgw.GetID(),
				Reason:      fmt.Sprintf("destination %s not allowed by Direct Connect gateway prefixes", dest.IP),
			}
		}
	}

	return []domain.Component{NewIPTarget(&domain.IPTargetData{IP: dest.IP, Port: dest.Port}, dxgw.accountID)}, nil
}

func (dxgw *DirectConnectGateway) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (dxgw *DirectConnectGateway) GetID() string {
	return fmt.Sprintf("%s:%s", dxgw.accountID, dxgw.data.ID)
}

func (dxgw *DirectConnectGateway) GetAccountID() string {
	return dxgw.accountID
}

func (dxgw *DirectConnectGateway) IsTerminal() bool {
	return true
}
