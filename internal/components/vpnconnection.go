package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type VPNConnection struct {
	data      *domain.VPNConnectionData
	accountID string
}

func NewVPNConnection(data *domain.VPNConnectionData, accountID string) *VPNConnection {
	return &VPNConnection{
		data:      data,
		accountID: accountID,
	}
}

func (vpn *VPNConnection) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if dest.IP == "" {
		return nil, &domain.BlockingError{
			ComponentID: vpn.GetID(),
			Reason:      "vpn connection requires a destination IP to evaluate",
		}
	}

	if vpn.data.State != "" && vpn.data.State != "available" {
		return nil, &domain.BlockingError{
			ComponentID: vpn.GetID(),
			Reason:      fmt.Sprintf("vpn connection state is %s, not available", vpn.data.State),
		}
	}

	if !vpn.data.HasUpTunnel {
		return nil, &domain.BlockingError{
			ComponentID: vpn.GetID(),
			Reason:      "no VPN tunnels are up",
		}
	}

	return []domain.Component{NewIPTarget(&domain.IPTargetData{IP: dest.IP, Port: dest.Port}, vpn.accountID)}, nil
}

func (vpn *VPNConnection) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (vpn *VPNConnection) GetID() string {
	return fmt.Sprintf("%s:%s", vpn.accountID, vpn.data.ID)
}

func (vpn *VPNConnection) GetAccountID() string {
	return vpn.accountID
}

func (vpn *VPNConnection) IsTerminal() bool {
	return true
}

func (vpn *VPNConnection) GetComponentType() string {
	return "VPNConnection"
}

func (vpn *VPNConnection) GetVPCID() string {
	return ""
}

func (vpn *VPNConnection) GetRegion() string {
	return ""
}

func (vpn *VPNConnection) GetSubnetID() string {
	return ""
}

func (vpn *VPNConnection) GetAvailabilityZone() string {
	return ""
}
