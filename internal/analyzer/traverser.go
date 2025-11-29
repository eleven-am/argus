package analyzer

import (
	"context"
	"errors"
	"net"

	"github.com/eleven-am/argus/internal/domain"
	resolverpkg "github.com/eleven-am/argus/internal/resolver"
)

func TestReachability(ctx context.Context, source, destination domain.Component, accountCtx domain.AccountContext) domain.ReachabilityResult {
	return TestReachabilityWithResolver(ctx, source, destination, accountCtx, nil)
}

func TestReachabilityWithResolver(ctx context.Context, source, destination domain.Component, accountCtx domain.AccountContext, resolver domain.DestinationResolver) domain.ReachabilityResult {
	if resolver == nil && accountCtx != nil {
		resolver = resolverpkg.NewSimpleResolver(accountCtx)
	}

	destTarget := destination.GetRoutingTarget()
	destTarget.Direction = "outbound"
	destTarget.SourceIsPrivate = isPrivateIPStr(source.GetRoutingTarget().IP)
	sourceTarget := source.GetRoutingTarget()
	sourceTarget.Direction = "inbound"
	sourceTarget.SourceIsPrivate = isPrivateIPStr(destTarget.IP)

	ctxWithResolver := &accountContextWithResolver{
		AccountContext: accountCtx,
		resolver:       resolver,
	}

	sourceAnalyzer := NewAnalyzerContext(ctx, ctxWithResolver)
	sourceResult := TraversePath(source, destTarget, destination.GetID(), sourceAnalyzer, resolver)

	destAnalyzer := NewAnalyzerContext(ctx, ctxWithResolver)
	destResult := TraversePath(destination, sourceTarget, source.GetID(), destAnalyzer, resolver)

	return domain.CombineResults(sourceResult, destResult)
}

func TraversePath(current domain.Component, destination domain.RoutingTarget, destinationID string, analyzerCtx domain.AnalyzerContext, resolver domain.DestinationResolver) domain.PathResult {
	analyzerCtx.MarkVisited(current)

	nextHops, err := current.GetNextHops(destination, analyzerCtx)
	if err != nil {
		return domain.BlockedResult{
			BlockingComponent: current,
			Reason:            err,
		}
	}

	filteredHops := filterVisited(nextHops, analyzerCtx)

	if IsDestinationReached(filteredHops, destination, destinationID) {
		return domain.SuccessResult{}
	}

	if len(filteredHops) == 0 {
		if isTerminalComponent(current) && isExternalDestination(destination.IP) {
			return domain.SuccessResult{}
		}
		if isFilterComponent(current) {
			return domain.SuccessResult{}
		}
		return domain.BlockedResult{
			BlockingComponent: current,
			Reason:            errors.New("no route to destination"),
		}
	}

	var lastBlockedResult domain.PathResult
	for _, hop := range filteredHops {
		result := TraversePath(hop, destination, destinationID, analyzerCtx, resolver)
		if !result.IsBlocked() {
			return result
		}
		lastBlockedResult = result
	}

	if lastBlockedResult != nil {
		return lastBlockedResult
	}

	return domain.BlockedResult{
		BlockingComponent: current,
		Reason:            errors.New("all paths blocked"),
	}
}

func isTerminalComponent(c domain.Component) bool {
	if tc, ok := c.(domain.TerminalComponent); ok {
		return tc.IsTerminal()
	}
	return false
}

func isFilterComponent(c domain.Component) bool {
	if fc, ok := c.(domain.FilterComponent); ok {
		return fc.IsFilter()
	}
	return false
}

func isExternalDestination(ip string) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return !isPrivateIP(parsed)
}

var analyzerPrivateCIDRs []*net.IPNet

func init() {
	blocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
		"::1/128",
	}
	for _, block := range blocks {
		if _, cidr, err := net.ParseCIDR(block); err == nil {
			analyzerPrivateCIDRs = append(analyzerPrivateCIDRs, cidr)
		}
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, cidr := range analyzerPrivateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateIPStr(ip string) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return isPrivateIP(parsed)
}

func filterVisited(hops []domain.Component, analyzerCtx domain.AnalyzerContext) []domain.Component {
	var filtered []domain.Component
	for _, hop := range hops {
		if !analyzerCtx.IsVisited(hop) {
			filtered = append(filtered, hop)
		}
	}
	return filtered
}

func IsDestinationReached(hops []domain.Component, destination domain.RoutingTarget, destinationID string) bool {
	for _, hop := range hops {
		if hop.GetID() == destinationID {
			return true
		}
		hopTarget := hop.GetRoutingTarget()
		if targetMatches(hopTarget, destination) {
			return true
		}
	}
	return false
}

func targetMatches(hopTarget, destination domain.RoutingTarget) bool {
	if destination.IP != "" {
		if hopTarget.IP != destination.IP {
			return false
		}
	}
	if destination.Port != 0 {
		if hopTarget.Port != destination.Port {
			return false
		}
	}
	if destination.Protocol != "" {
		if hopTarget.Protocol != destination.Protocol {
			return false
		}
	}
	if destination.IP == "" && destination.Port == 0 && destination.Protocol == "" {
		return false
	}
	return true
}

type accountContextWithResolver struct {
	domain.AccountContext
	resolver domain.DestinationResolver
}

func (a *accountContextWithResolver) GetResolver() domain.DestinationResolver {
	return a.resolver
}
