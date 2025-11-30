package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type TransitGatewayAttachment struct {
	data      *domain.TGWAttachmentData
	accountID string
}

func NewTransitGatewayAttachment(data *domain.TGWAttachmentData, accountID string) *TransitGatewayAttachment {
	return &TransitGatewayAttachment{
		data:      data,
		accountID: accountID,
	}
}

func (tga *TransitGatewayAttachment) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if tga.data.State != "" && tga.data.State != "available" {
		return nil, &domain.BlockingError{
			ComponentID: tga.GetID(),
			Reason:      fmt.Sprintf("TGW attachment state is %s, not available", tga.data.State),
		}
	}

	tgwClient, err := analyzerCtx.GetAccountContext().GetClient(tga.data.TGWAccountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	tgwData, err := tgwClient.GetTransitGateway(ctx, tga.data.TransitGatewayID)
	if err != nil {
		return nil, err
	}

	return []domain.Component{NewTransitGateway(tgwData, tga.data.TGWAccountID, tga.data.ID)}, nil
}

func (tga *TransitGatewayAttachment) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (tga *TransitGatewayAttachment) GetID() string {
	return fmt.Sprintf("%s:%s", tga.accountID, tga.data.ID)
}

func (tga *TransitGatewayAttachment) GetAccountID() string {
	return tga.accountID
}

func (tga *TransitGatewayAttachment) GetComponentType() string {
	return "TransitGatewayAttachment"
}

func (tga *TransitGatewayAttachment) GetVPCID() string {
	return tga.data.VPCID
}

func (tga *TransitGatewayAttachment) GetRegion() string {
	return ""
}

func (tga *TransitGatewayAttachment) GetSubnetID() string {
	if len(tga.data.SubnetIDs) > 0 {
		return tga.data.SubnetIDs[0]
	}
	return ""
}

func (tga *TransitGatewayAttachment) GetAvailabilityZone() string {
	return ""
}

type TransitGateway struct {
	data                *domain.TransitGatewayData
	accountID           string
	ingressAttachmentID string
}

func NewTransitGateway(data *domain.TransitGatewayData, accountID, ingressAttachmentID string) *TransitGateway {
	return &TransitGateway{
		data:                data,
		accountID:           accountID,
		ingressAttachmentID: ingressAttachmentID,
	}
}

func (tgw *TransitGateway) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	allowedRTIDs := tgw.getAllowedRouteTables()

	prefixCache := make(map[string]int)
	matchedRoute, matchedAttachment := tgw.findBestRoute(dest, allowedRTIDs, analyzerCtx, prefixCache)

	if matchedRoute == nil || matchedAttachment == nil {
		return nil, &domain.BlockingError{
			ComponentID: tgw.GetID(),
			Reason:      fmt.Sprintf("no transit gateway route to %s for attachment %s", dest.IP, tgw.ingressAttachmentID),
		}
	}

	if matchedAttachment.State != "" && matchedAttachment.State != "available" {
		return nil, &domain.BlockingError{
			ComponentID: tgw.GetID(),
			Reason:      fmt.Sprintf("target attachment %s state is %s, not available", matchedAttachment.ID, matchedAttachment.State),
		}
	}

	return tgw.dispatchToAttachment(matchedAttachment, analyzerCtx)
}

func (tgw *TransitGateway) getAllowedRouteTables() map[string]bool {
	allowed := make(map[string]bool)

	if tgw.ingressAttachmentID == "" {
		for _, rt := range tgw.data.RouteTables {
			allowed[rt.ID] = true
		}
		return allowed
	}

	for _, rt := range tgw.data.RouteTables {
		for _, assoc := range rt.Associations {
			if assoc.AttachmentID == tgw.ingressAttachmentID && assoc.State == "associated" {
				allowed[rt.ID] = true
			}
		}
		for _, prop := range rt.Propagations {
			if prop.AttachmentID == tgw.ingressAttachmentID && prop.State == "enabled" {
				allowed[rt.ID] = true
			}
		}
	}

	return allowed
}

func (tgw *TransitGateway) findBestRoute(dest domain.RoutingTarget, allowedRTIDs map[string]bool, analyzerCtx domain.AnalyzerContext, prefixCache map[string]int) (*domain.TGWRoute, *domain.TGWRouteAttachment) {
	var bestRoute *domain.TGWRoute
	var bestAttachment *domain.TGWRouteAttachment
	longestPrefix := -1

	for i := range tgw.data.RouteTables {
		rt := &tgw.data.RouteTables[i]

		if !allowedRTIDs[rt.ID] {
			continue
		}

		for j := range rt.Routes {
			route := &rt.Routes[j]

			if route.State != "active" {
				continue
			}

			matchPrefix := -1
			if route.DestinationCIDR != "" && IPMatchesCIDR(dest.IP, route.DestinationCIDR) {
				matchPrefix = route.PrefixLength
			} else if route.DestinationPrefixListID != "" {
				matchPrefix = tgw.matchPrefixList(dest.IP, route.DestinationPrefixListID, analyzerCtx, prefixCache)
			}

			if matchPrefix <= longestPrefix || matchPrefix < 0 {
				continue
			}

			attachment := tgw.selectActiveAttachment(route)
			if attachment == nil {
				continue
			}

			bestRoute = route
			bestAttachment = attachment
			longestPrefix = matchPrefix
		}
	}

	return bestRoute, bestAttachment
}

func (tgw *TransitGateway) matchPrefixList(ip, plID string, analyzerCtx domain.AnalyzerContext, prefixCache map[string]int) int {
	if val, ok := prefixCache[plID+":"+ip]; ok {
		return val
	}
	if analyzerCtx == nil || analyzerCtx.GetAccountContext() == nil {
		return -1
	}
	client, err := analyzerCtx.GetAccountContext().GetClient(tgw.accountID)
	if err != nil {
		return -1
	}
	pl, err := client.GetManagedPrefixList(analyzerCtx.Context(), plID)
	if err != nil {
		prefixCache[plID+":"+ip] = -1
		return -1
	}

	longest := -1
	for _, entry := range pl.Entries {
		if IPMatchesCIDR(ip, entry.CIDR) {
			p := getPrefixLength(entry.CIDR)
			if p > longest {
				longest = p
			}
		}
	}
	prefixCache[plID+":"+ip] = longest
	return longest
}

func (tgw *TransitGateway) selectActiveAttachment(route *domain.TGWRoute) *domain.TGWRouteAttachment {
	for i := range route.Attachments {
		att := &route.Attachments[i]
		if att.State == "" || att.State == "available" {
			return att
		}
	}
	return nil
}

func (tgw *TransitGateway) dispatchToAttachment(att *domain.TGWRouteAttachment, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	targetClient, err := analyzerCtx.GetAccountContext().GetClient(att.OwnerID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	switch att.Type {
	case "vpc":
		attachmentData, err := targetClient.GetTransitGatewayAttachmentByID(ctx, att.ID)
		if err != nil {
			return nil, err
		}
		return []domain.Component{NewTransitGatewayVPCAttachmentInbound(attachmentData, att.OwnerID)}, nil

	case "peering":
		peeringData, err := targetClient.GetTGWPeeringAttachment(ctx, att.ID)
		if err != nil {
			return nil, err
		}
		return []domain.Component{NewTGWPeeringAttachment(peeringData, att.OwnerID)}, nil

	case "vpn":
		vpnData, err := targetClient.GetVPNConnection(ctx, att.ResourceID)
		if err != nil {
			return nil, err
		}
		return []domain.Component{NewVPNConnection(vpnData, att.OwnerID)}, nil

	case "direct-connect-gateway":
		dxgwData, err := targetClient.GetDirectConnectGateway(ctx, att.ResourceID)
		if err != nil {
			return nil, err
		}
		return []domain.Component{NewDirectConnectGateway(dxgwData, att.OwnerID)}, nil

	default:
		return nil, &domain.BlockingError{
			ComponentID: tgw.GetID(),
			Reason:      fmt.Sprintf("unsupported TGW attachment type: %s", att.Type),
		}
	}
}

func (tgw *TransitGateway) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (tgw *TransitGateway) GetID() string {
	return fmt.Sprintf("%s:%s", tgw.accountID, tgw.data.ID)
}

func (tgw *TransitGateway) GetAccountID() string {
	return tgw.accountID
}

func (tgw *TransitGateway) GetComponentType() string {
	return "TransitGateway"
}

func (tgw *TransitGateway) GetVPCID() string {
	return ""
}

func (tgw *TransitGateway) GetRegion() string {
	return ""
}

func (tgw *TransitGateway) GetSubnetID() string {
	return ""
}

func (tgw *TransitGateway) GetAvailabilityZone() string {
	return ""
}

type TransitGatewayVPCAttachmentInbound struct {
	data      *domain.TGWAttachmentData
	accountID string
}

func NewTransitGatewayVPCAttachmentInbound(data *domain.TGWAttachmentData, accountID string) *TransitGatewayVPCAttachmentInbound {
	return &TransitGatewayVPCAttachmentInbound{
		data:      data,
		accountID: accountID,
	}
}

func (tga *TransitGatewayVPCAttachmentInbound) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if tga.data.State != "" && tga.data.State != "available" {
		return nil, &domain.BlockingError{
			ComponentID: tga.GetID(),
			Reason:      fmt.Sprintf("TGW VPC attachment state is %s, not available", tga.data.State),
		}
	}

	client, err := analyzerCtx.GetAccountContext().GetClient(tga.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	for _, subnetID := range tga.data.SubnetIDs {
		subnetData, err := client.GetSubnet(ctx, subnetID)
		if err != nil {
			continue
		}
		if IPMatchesCIDR(dest.IP, subnetData.CIDRBlock) {
			rtData, err := client.GetRouteTable(ctx, subnetData.RouteTableID)
			if err != nil {
				return nil, err
			}
			return []domain.Component{NewRouteTable(rtData, tga.accountID)}, nil
		}
	}

	vpcData, err := client.GetVPC(ctx, tga.data.VPCID)
	if err != nil {
		return nil, err
	}

	rtData, err := client.GetRouteTable(ctx, vpcData.MainRouteTableID)
	if err != nil {
		return nil, err
	}

	return []domain.Component{NewRouteTable(rtData, tga.accountID)}, nil
}

func (tga *TransitGatewayVPCAttachmentInbound) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (tga *TransitGatewayVPCAttachmentInbound) GetID() string {
	return fmt.Sprintf("%s:%s:inbound", tga.accountID, tga.data.ID)
}

func (tga *TransitGatewayVPCAttachmentInbound) GetAccountID() string {
	return tga.accountID
}

func (tga *TransitGatewayVPCAttachmentInbound) GetComponentType() string {
	return "TransitGatewayVPCAttachmentInbound"
}

func (tga *TransitGatewayVPCAttachmentInbound) GetVPCID() string {
	return tga.data.VPCID
}

func (tga *TransitGatewayVPCAttachmentInbound) GetRegion() string {
	return ""
}

func (tga *TransitGatewayVPCAttachmentInbound) GetSubnetID() string {
	if len(tga.data.SubnetIDs) > 0 {
		return tga.data.SubnetIDs[0]
	}
	return ""
}

func (tga *TransitGatewayVPCAttachmentInbound) GetAvailabilityZone() string {
	return ""
}

type TGWPeeringAttachment struct {
	data      *domain.TGWPeeringAttachmentData
	accountID string
}

func NewTGWPeeringAttachment(data *domain.TGWPeeringAttachmentData, accountID string) *TGWPeeringAttachment {
	return &TGWPeeringAttachment{
		data:      data,
		accountID: accountID,
	}
}

func (tpa *TGWPeeringAttachment) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	peerClient, err := analyzerCtx.GetAccountContext().GetClient(tpa.data.PeerAccountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	peerTGWData, err := peerClient.GetTransitGateway(ctx, tpa.data.PeerTransitGatewayID)
	if err != nil {
		return nil, err
	}

	return []domain.Component{NewTransitGateway(peerTGWData, tpa.data.PeerAccountID, tpa.data.ID)}, nil
}

func (tpa *TGWPeeringAttachment) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (tpa *TGWPeeringAttachment) GetID() string {
	return fmt.Sprintf("%s:%s", tpa.accountID, tpa.data.ID)
}

func (tpa *TGWPeeringAttachment) GetAccountID() string {
	return tpa.accountID
}

func (tpa *TGWPeeringAttachment) GetComponentType() string {
	return "TGWPeeringAttachment"
}

func (tpa *TGWPeeringAttachment) GetVPCID() string {
	return ""
}

func (tpa *TGWPeeringAttachment) GetRegion() string {
	return ""
}

func (tpa *TGWPeeringAttachment) GetSubnetID() string {
	return ""
}

func (tpa *TGWPeeringAttachment) GetAvailabilityZone() string {
	return ""
}
