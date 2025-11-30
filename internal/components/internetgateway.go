package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type InternetGateway struct {
	data      *domain.InternetGatewayData
	accountID string
}

func NewInternetGateway(data *domain.InternetGatewayData, accountID string) *InternetGateway {
	return &InternetGateway{
		data:      data,
		accountID: accountID,
	}
}

func (igw *InternetGateway) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if !isExternalIP(dest.IP) {
		return nil, &domain.BlockingError{
			ComponentID: igw.GetID(),
			Reason:      "internet gateway can only route to external (public) IP addresses",
		}
	}
	if dest.Direction == "outbound" && dest.SourceIsPrivate && !isExternalIP(dest.IP) {
		return nil, &domain.BlockingError{
			ComponentID: igw.GetID(),
			Reason:      "internet gateway outbound requires external destination",
		}
	}
	if analyzerCtx == nil || analyzerCtx.GetAccountContext() == nil {
		return nil, &domain.BlockingError{
			ComponentID: igw.GetID(),
			Reason:      "internet gateway requires analyzer context for VPC validation",
		}
	}
	client, err := analyzerCtx.GetAccountContext().GetClient(igw.accountID)
	if err != nil {
		return nil, err
	}
	if igw.data.VPCID == "" {
		return nil, &domain.BlockingError{
			ComponentID: igw.GetID(),
			Reason:      "internet gateway missing VPC attachment",
		}
	}
	ctx := analyzerCtx.Context()
	vpc, err := client.GetVPC(ctx, igw.data.VPCID)
	if err != nil {
		return nil, err
	}
	if vpc.CIDRBlock != "" && !IPMatchesCIDR(dest.IP, vpc.CIDRBlock) && (vpc.IPv6CIDRBlock == "" || !IPMatchesCIDR(dest.IP, vpc.IPv6CIDRBlock)) && dest.Direction == "inbound" {
		return nil, &domain.BlockingError{
			ComponentID: igw.GetID(),
			Reason:      fmt.Sprintf("destination %s not within attached VPC %s", dest.IP, vpc.ID),
		}
	}
	return []domain.Component{NewIPTarget(&domain.IPTargetData{IP: dest.IP, Port: dest.Port}, igw.accountID)}, nil
}

func (igw *InternetGateway) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (igw *InternetGateway) GetID() string {
	return fmt.Sprintf("%s:%s", igw.accountID, igw.data.ID)
}

func (igw *InternetGateway) GetAccountID() string {
	return igw.accountID
}

func (igw *InternetGateway) IsTerminal() bool {
	return true
}

func (igw *InternetGateway) GetComponentType() string {
	return "InternetGateway"
}

func (igw *InternetGateway) GetVPCID() string {
	return igw.data.VPCID
}

func (igw *InternetGateway) GetRegion() string {
	return ""
}

func (igw *InternetGateway) GetSubnetID() string {
	return ""
}

func (igw *InternetGateway) GetAvailabilityZone() string {
	return ""
}
