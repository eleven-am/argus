package components

import (
	"fmt"
	"net"

	"github.com/eleven-am/argus/internal/domain"
)

type EgressOnlyInternetGateway struct {
	data      *domain.EgressOnlyInternetGatewayData
	accountID string
}

func NewEgressOnlyInternetGateway(data *domain.EgressOnlyInternetGatewayData, accountID string) *EgressOnlyInternetGateway {
	return &EgressOnlyInternetGateway{
		data:      data,
		accountID: accountID,
	}
}

func (eigw *EgressOnlyInternetGateway) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if dest.Direction != "outbound" {
		return nil, &domain.BlockingError{
			ComponentID: eigw.GetID(),
			Reason:      "egress-only internet gateway only allows outbound traffic",
		}
	}

	ip := net.ParseIP(dest.IP)
	if ip == nil {
		return nil, &domain.BlockingError{
			ComponentID: eigw.GetID(),
			Reason:      fmt.Sprintf("invalid IP address: %s", dest.IP),
		}
	}

	if ip.To4() != nil {
		return nil, &domain.BlockingError{
			ComponentID: eigw.GetID(),
			Reason:      "egress-only internet gateway only supports IPv6 traffic",
		}
	}

	if !isExternalIP(dest.IP) {
		return nil, &domain.BlockingError{
			ComponentID: eigw.GetID(),
			Reason:      "egress-only internet gateway can only route to external (public) IPv6 addresses",
		}
	}

	return []domain.Component{NewIPTarget(&domain.IPTargetData{IP: dest.IP, Port: dest.Port}, eigw.accountID)}, nil
}

func (eigw *EgressOnlyInternetGateway) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (eigw *EgressOnlyInternetGateway) GetID() string {
	return fmt.Sprintf("%s:%s", eigw.accountID, eigw.data.ID)
}

func (eigw *EgressOnlyInternetGateway) GetAccountID() string {
	return eigw.accountID
}

func (eigw *EgressOnlyInternetGateway) IsTerminal() bool {
	return true
}

func (eigw *EgressOnlyInternetGateway) GetComponentType() string {
	return "EgressOnlyInternetGateway"
}

func (eigw *EgressOnlyInternetGateway) GetVPCID() string {
	return eigw.data.VPCID
}

func (eigw *EgressOnlyInternetGateway) GetRegion() string {
	return ""
}

func (eigw *EgressOnlyInternetGateway) GetSubnetID() string {
	return ""
}

func (eigw *EgressOnlyInternetGateway) GetAvailabilityZone() string {
	return ""
}
