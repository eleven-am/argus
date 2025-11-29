package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type CarrierGateway struct {
	id        string
	accountID string
}

func NewCarrierGateway(id, accountID string) *CarrierGateway {
	return &CarrierGateway{
		id:        id,
		accountID: accountID,
	}
}

func (cgw *CarrierGateway) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if dest.IP == "" {
		return nil, &domain.BlockingError{
			ComponentID: cgw.GetID(),
			Reason:      "carrier gateway route requires a destination IP",
		}
	}

	if dest.Direction == "inbound" {
		return nil, &domain.BlockingError{
			ComponentID: cgw.GetID(),
			Reason:      "carrier gateway supports egress only; inbound flows are not accepted",
		}
	}

	if !isExternalIP(dest.IP) {
		return nil, &domain.BlockingError{
			ComponentID: cgw.GetID(),
			Reason:      "carrier gateway routes only support egress to external destinations",
		}
	}

	return []domain.Component{NewIPTarget(&domain.IPTargetData{IP: dest.IP, Port: dest.Port}, cgw.accountID)}, nil
}

func (cgw *CarrierGateway) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (cgw *CarrierGateway) GetID() string {
	return fmt.Sprintf("%s:%s", cgw.accountID, cgw.id)
}

func (cgw *CarrierGateway) GetAccountID() string {
	return cgw.accountID
}

func (cgw *CarrierGateway) IsTerminal() bool {
	return true
}

func (cgw *CarrierGateway) GetComponentType() string {
	return "CarrierGateway"
}
