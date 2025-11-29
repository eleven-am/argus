package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type IPTarget struct {
	data      *domain.IPTargetData
	accountID string
}

func NewIPTarget(data *domain.IPTargetData, accountID string) *IPTarget {
	return &IPTarget{
		data:      data,
		accountID: accountID,
	}
}

func (ip *IPTarget) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	return []domain.Component{}, nil
}

func (ip *IPTarget) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{
		IP:   ip.data.IP,
		Port: ip.data.Port,
	}
}

func (ip *IPTarget) GetID() string {
	return fmt.Sprintf("%s:ip:%s:%d", ip.accountID, ip.data.IP, ip.data.Port)
}

func (ip *IPTarget) GetAccountID() string {
	return ip.accountID
}

func (ip *IPTarget) IsTerminal() bool {
	return true
}

func (ip *IPTarget) GetComponentType() string {
	return "IPTarget"
}
