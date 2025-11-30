package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type NATGateway struct {
	data      *domain.NATGatewayData
	accountID string
}

func NewNATGateway(data *domain.NATGatewayData, accountID string) *NATGateway {
	return &NATGateway{
		data:      data,
		accountID: accountID,
	}
}

func (nat *NATGateway) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if dest.Direction == "inbound" {
		return nil, &domain.BlockingError{
			ComponentID: nat.GetID(),
			Reason:      "NAT gateway does not accept unsolicited inbound traffic",
		}
	}

	if !isExternalIP(dest.IP) {
		return nil, &domain.BlockingError{
			ComponentID: nat.GetID(),
			Reason:      "NAT gateway can only route to external (public) IP addresses",
		}
	}
	if dest.Direction == "outbound" && !dest.SourceIsPrivate {
		return nil, &domain.BlockingError{
			ComponentID: nat.GetID(),
			Reason:      "NAT gateway expects private source IP for outbound traffic",
		}
	}
	client, err := analyzerCtx.GetAccountContext().GetClient(nat.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	if nat.data.SubnetID == "" {
		return nil, &domain.BlockingError{
			ComponentID: nat.GetID(),
			Reason:      "NAT gateway missing subnet data",
		}
	}

	subnetData, err := client.GetSubnet(ctx, nat.data.SubnetID)
	if err != nil {
		return nil, err
	}

	return []domain.Component{NewSubnet(subnetData, nat.accountID)}, nil
}

func (nat *NATGateway) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (nat *NATGateway) GetID() string {
	return fmt.Sprintf("%s:%s", nat.accountID, nat.data.ID)
}

func (nat *NATGateway) GetAccountID() string {
	return nat.accountID
}

func (nat *NATGateway) GetComponentType() string {
	return "NATGateway"
}

func (nat *NATGateway) GetVPCID() string {
	return ""
}

func (nat *NATGateway) GetRegion() string {
	return ""
}

func (nat *NATGateway) GetSubnetID() string {
	return nat.data.SubnetID
}

func (nat *NATGateway) GetAvailabilityZone() string {
	return ""
}
