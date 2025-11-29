package components

import (
	"fmt"
	"strings"

	"github.com/eleven-am/argus/internal/domain"
)

type RouteTable struct {
	data      *domain.RouteTableData
	accountID string
}

func NewRouteTable(data *domain.RouteTableData, accountID string) *RouteTable {
	return &RouteTable{
		data:      data,
		accountID: accountID,
	}
}

func (rt *RouteTable) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	var matchedRoute *domain.Route
	longestPrefix := -1

	for i, route := range rt.data.Routes {
		matches, prefixLen := rt.routeMatches(route, dest.IP, analyzerCtx)
		if matches && prefixLen > longestPrefix {
			matchedRoute = &rt.data.Routes[i]
			longestPrefix = prefixLen
		}
	}

	if matchedRoute == nil {
		return nil, &domain.BlockingError{
			ComponentID: rt.GetID(),
			Reason:      fmt.Sprintf("no route to %s", dest.IP),
		}
	}

	ctx := analyzerCtx.Context()
	accountCtx := analyzerCtx.GetAccountContext()

	if matchedRoute.TargetType == "local" {
		if accountCtx != nil {
			client, err := accountCtx.GetClient(rt.accountID)
			if err != nil {
				return nil, err
			}
			vpc, err := client.GetVPC(ctx, rt.data.VPCID)
			if err != nil {
				return nil, err
			}
			if vpc.CIDRBlock != "" && !IPMatchesCIDR(dest.IP, vpc.CIDRBlock) && (vpc.IPv6CIDRBlock == "" || !IPMatchesCIDR(dest.IP, vpc.IPv6CIDRBlock)) {
				return nil, &domain.BlockingError{
					ComponentID: rt.GetID(),
					Reason:      fmt.Sprintf("local route but destination %s not in VPC %s CIDR", dest.IP, vpc.CIDRBlock),
				}
			}

			if rp, ok := accountCtx.(domain.ResolverProvider); ok {
				if resolver := rp.GetResolver(); resolver != nil {
					if comp, err := resolver.ResolveByIP(ctx, rt.accountID, rt.data.VPCID, dest.IP); err == nil && comp != nil {
						return []domain.Component{comp}, nil
					}
				}
			}
		}
		return []domain.Component{NewIPTarget(&domain.IPTargetData{IP: dest.IP, Port: dest.Port}, rt.accountID)}, nil
	}

	client, err := accountCtx.GetClient(rt.accountID)
	if err != nil {
		return nil, err
	}

	switch matchedRoute.TargetType {
	case "internet-gateway":
		igwData, err := client.GetInternetGateway(ctx, matchedRoute.TargetID)
		if err != nil {
			return nil, err
		}
		return []domain.Component{NewInternetGateway(igwData, rt.accountID)}, nil

	case "nat-gateway":
		natData, err := client.GetNATGateway(ctx, matchedRoute.TargetID)
		if err != nil {
			return nil, err
		}
		return []domain.Component{NewNATGateway(natData, rt.accountID)}, nil

	case "transit-gateway":
		tgwAttachment, err := client.GetTransitGatewayAttachment(ctx, rt.data.VPCID, matchedRoute.TargetID)
		if err != nil {
			return nil, err
		}
		return []domain.Component{NewTransitGatewayAttachment(tgwAttachment, rt.accountID)}, nil

	case "vpc-endpoint":
		endpointData, err := client.GetVPCEndpoint(ctx, matchedRoute.TargetID)
		if err != nil {
			return nil, err
		}
		if strings.Contains(endpointData.ServiceName, ".gwlb") || endpointData.Type == "GatewayLoadBalancer" {
			return []domain.Component{NewGWLBEndpoint(endpointData, rt.accountID)}, nil
		}
		return []domain.Component{NewVPCEndpoint(endpointData, rt.accountID)}, nil

	case "vpc-peering":
		peeringData, err := client.GetVPCPeering(ctx, matchedRoute.TargetID)
		if err != nil {
			return nil, err
		}
		return []domain.Component{NewVPCPeering(peeringData, rt.accountID, rt.data.VPCID)}, nil

	case "vpn-gateway":
		vgwData, err := client.GetVirtualPrivateGateway(ctx, matchedRoute.TargetID)
		if err != nil {
			return nil, err
		}
		return []domain.Component{NewVirtualPrivateGateway(vgwData, rt.accountID)}, nil

	case "network-interface":
		return []domain.Component{NewNetworkInterface(matchedRoute.TargetID, rt.accountID)}, nil

	case "local-gateway":
		return []domain.Component{NewLocalGateway(matchedRoute.TargetID, rt.accountID)}, nil

	case "carrier-gateway":
		return []domain.Component{NewCarrierGateway(matchedRoute.TargetID, rt.accountID)}, nil

	default:
		return nil, &domain.BlockingError{
			ComponentID: rt.GetID(),
			Reason:      fmt.Sprintf("unknown route target type: %s", matchedRoute.TargetType),
		}
	}
}

func (rt *RouteTable) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (rt *RouteTable) GetID() string {
	return fmt.Sprintf("%s:%s", rt.accountID, rt.data.ID)
}

func (rt *RouteTable) GetAccountID() string {
	return rt.accountID
}

func (rt *RouteTable) GetComponentType() string {
	return "RouteTable"
}

func (rt *RouteTable) GetVPCID() string {
	return rt.data.VPCID
}

func (rt *RouteTable) GetRegion() string {
	return ""
}

func (rt *RouteTable) GetSubnetID() string {
	return ""
}

func (rt *RouteTable) GetAvailabilityZone() string {
	return ""
}

func (rt *RouteTable) routeMatches(route domain.Route, ip string, analyzerCtx domain.AnalyzerContext) (bool, int) {
	if route.DestinationCIDR != "" {
		if IPMatchesCIDR(ip, route.DestinationCIDR) {
			return true, route.PrefixLength
		}
	}

	if route.DestinationIPv6CIDR != "" {
		if IPMatchesCIDR(ip, route.DestinationIPv6CIDR) {
			prefixLen := getPrefixLength(route.DestinationIPv6CIDR)
			return true, prefixLen
		}
	}

	if route.DestinationPrefixListID != "" {
		ok, plen, err := rt.matchesPrefixList(ip, route.DestinationPrefixListID, analyzerCtx)
		if err != nil {
			return false, -1
		}
		return ok, plen
	}

	return false, -1
}

func (rt *RouteTable) matchesPrefixList(ip, plID string, analyzerCtx domain.AnalyzerContext) (bool, int, error) {
	if analyzerCtx == nil {
		return false, -1, nil
	}
	client, err := analyzerCtx.GetAccountContext().GetClient(rt.accountID)
	if err != nil {
		return false, -1, err
	}
	pl, err := client.GetManagedPrefixList(analyzerCtx.Context(), plID)
	if err != nil {
		return false, -1, err
	}

	longestPrefix := -1
	for _, entry := range pl.Entries {
		if IPMatchesCIDR(ip, entry.CIDR) {
			prefixLen := getPrefixLength(entry.CIDR)
			if prefixLen > longestPrefix {
				longestPrefix = prefixLen
			}
		}
	}

	return longestPrefix >= 0, longestPrefix, nil
}

func getPrefixLength(cidr string) int {
	for i := len(cidr) - 1; i >= 0; i-- {
		if cidr[i] == '/' {
			length := 0
			for j := i + 1; j < len(cidr); j++ {
				length = length*10 + int(cidr[j]-'0')
			}
			return length
		}
	}
	return 0
}
