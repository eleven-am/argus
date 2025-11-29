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
