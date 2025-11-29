package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type DirectConnectOnPrem struct {
	data      *domain.DirectConnectOnPremData
	accountID string
}

func NewDirectConnectOnPrem(data *domain.DirectConnectOnPremData, accountID string) *DirectConnectOnPrem {
	return &DirectConnectOnPrem{
		data:      data,
		accountID: accountID,
	}
}

func (d *DirectConnectOnPrem) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if d.data.AttachmentState != "" && d.data.AttachmentState != "attached" && d.data.AttachmentState != "available" {
		return nil, &domain.BlockingError{
			ComponentID: d.GetID(),
			Reason:      fmt.Sprintf("Direct Connect Gateway attachment state is %s, not attached", d.data.AttachmentState),
		}
	}

	if d.data.OnPremCIDR != "" && len(d.data.AllowedPrefixes) > 0 {
		allowed := false
		for _, prefix := range d.data.AllowedPrefixes {
			if CIDROverlaps(d.data.OnPremCIDR, prefix) || IPMatchesCIDR(d.data.SourceIP, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, &domain.BlockingError{
				ComponentID: d.GetID(),
				Reason:      fmt.Sprintf("on-prem CIDR %s not in Direct Connect allowed prefixes", d.data.OnPremCIDR),
			}
		}
	}

	if d.data.DXGWID == "" {
		return nil, &domain.BlockingError{
			ComponentID: d.GetID(),
			Reason:      "Direct Connect Gateway ID not configured for on-prem source",
		}
	}

	client, err := analyzerCtx.GetAccountContext().GetClient(d.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	dxgwData, err := client.GetDirectConnectGateway(ctx, d.data.DXGWID)
	if err != nil {
		return nil, err
	}
	if dxgwData == nil {
		return nil, &domain.BlockingError{
			ComponentID: d.GetID(),
			Reason:      fmt.Sprintf("Direct Connect Gateway %s not found", d.data.DXGWID),
		}
	}

	dxgw := NewDirectConnectGateway(dxgwData, d.accountID)
	return []domain.Component{dxgw}, nil
}

func (d *DirectConnectOnPrem) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{
		IP:              d.data.SourceIP,
		Protocol:        "tcp",
		SourceIsPrivate: true,
	}
}

func (d *DirectConnectOnPrem) GetID() string {
	id := d.data.SourceIP
	if id == "" {
		id = d.data.OnPremCIDR
	}
	return fmt.Sprintf("%s:dxonprem:%s", d.accountID, id)
}

func (d *DirectConnectOnPrem) GetAccountID() string {
	return d.accountID
}

func (d *DirectConnectOnPrem) GetComponentType() string {
	return "DirectConnectOnPrem"
}

func (d *DirectConnectOnPrem) GetVPCID() string {
	return ""
}

func (d *DirectConnectOnPrem) GetRegion() string {
	return ""
}

func (d *DirectConnectOnPrem) GetSubnetID() string {
	return ""
}

func (d *DirectConnectOnPrem) GetAvailabilityZone() string {
	return ""
}
