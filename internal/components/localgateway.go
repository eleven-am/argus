package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type LocalGateway struct {
	id        string
	accountID string
}

func NewLocalGateway(id, accountID string) *LocalGateway {
	return &LocalGateway{
		id:        id,
		accountID: accountID,
	}
}

func (lgw *LocalGateway) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if dest.IP == "" {
		return nil, &domain.BlockingError{
			ComponentID: lgw.GetID(),
			Reason:      "local gateway target requires a destination IP",
		}
	}

	if !isExternalIP(dest.IP) {
		return nil, &domain.BlockingError{
			ComponentID: lgw.GetID(),
			Reason:      "local gateway routes hand off to on-prem/external; destination is not external",
		}
	}

	return []domain.Component{NewIPTarget(&domain.IPTargetData{IP: dest.IP, Port: dest.Port}, lgw.accountID)}, nil
}

func (lgw *LocalGateway) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (lgw *LocalGateway) GetID() string {
	return fmt.Sprintf("%s:%s", lgw.accountID, lgw.id)
}

func (lgw *LocalGateway) GetAccountID() string {
	return lgw.accountID
}

func (lgw *LocalGateway) IsTerminal() bool {
	return true
}

func (lgw *LocalGateway) GetComponentType() string {
	return "LocalGateway"
}

func (lgw *LocalGateway) GetVPCID() string {
	return ""
}

func (lgw *LocalGateway) GetRegion() string {
	return ""
}

func (lgw *LocalGateway) GetSubnetID() string {
	return ""
}

func (lgw *LocalGateway) GetAvailabilityZone() string {
	return ""
}
