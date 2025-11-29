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
		resolver = resolverpkg.NewResolver(accountCtx)
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
	forwardTrace := domain.NewPathTrace()
	sourceResult := TraversePathWithTrace(source, destTarget, destination.GetID(), sourceAnalyzer, resolver, forwardTrace, domain.HopLineage{})

	destAnalyzer := NewAnalyzerContext(ctx, ctxWithResolver)
	returnTrace := domain.NewPathTrace()
	destResult := TraversePathWithTrace(destination, sourceTarget, source.GetID(), destAnalyzer, resolver, returnTrace, domain.HopLineage{})

	return domain.CombineResultsWithTrace(sourceResult, destResult, forwardTrace, returnTrace)
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

func TraversePathWithTrace(current domain.Component, destination domain.RoutingTarget, destinationID string, analyzerCtx domain.AnalyzerContext, resolver domain.DestinationResolver, trace *domain.PathTrace, lineage domain.HopLineage) domain.PathResult {
	analyzerCtx.MarkVisited(current)

	action := inferHopAction(current)
	hop := domain.HopFromComponent(current, lineage, action, "")
	trace.AddHop(hop)

	nextHops, err := current.GetNextHops(destination, analyzerCtx)
	if err != nil {
		hop.Action = domain.HopActionBlocked
		hop.Details = err.Error()
		trace.BlockedAt = hop
		trace.Success = false
		return domain.BlockedResult{
			BlockingComponent: current,
			Reason:            err,
		}
	}

	filteredHops := filterVisited(nextHops, analyzerCtx)

	if IsDestinationReached(filteredHops, destination, destinationID) {
		hop.Action = domain.HopActionTerminal
		hop.Details = "destination reached"
		trace.MarkSuccess()
		return domain.SuccessResult{}
	}

	if len(filteredHops) == 0 {
		if isTerminalComponent(current) && isExternalDestination(destination.IP) {
			hop.Action = domain.HopActionTerminal
			hop.Details = "external destination via terminal"
			trace.MarkSuccess()
			return domain.SuccessResult{}
		}
		if isFilterComponent(current) {
			hop.Details = "filter passed"
			trace.MarkSuccess()
			return domain.SuccessResult{}
		}
		hop.Action = domain.HopActionBlocked
		hop.Details = "no route to destination"
		trace.BlockedAt = hop
		trace.Success = false
		return domain.BlockedResult{
			BlockingComponent: current,
			Reason:            errors.New("no route to destination"),
		}
	}

	var lastBlockedResult domain.PathResult
	for _, nextHop := range filteredHops {
		nextLineage := inferLineage(current, nextHop)
		branchTrace := trace.Clone()
		result := TraversePathWithTrace(nextHop, destination, destinationID, analyzerCtx, resolver, branchTrace, nextLineage)
		if !result.IsBlocked() {
			trace.Hops = branchTrace.Hops
			trace.Success = branchTrace.Success
			trace.BlockedAt = branchTrace.BlockedAt
			return result
		}
		lastBlockedResult = result
	}

	if lastBlockedResult != nil {
		return lastBlockedResult
	}

	hop.Action = domain.HopActionBlocked
	hop.Details = "all paths blocked"
	trace.BlockedAt = hop
	trace.Success = false
	return domain.BlockedResult{
		BlockingComponent: current,
		Reason:            errors.New("all paths blocked"),
	}
}

func inferHopAction(c domain.Component) domain.HopAction {
	switch c.GetComponentType() {
	case "SecurityGroup", "NACL":
		return domain.HopActionAllowed
	case "RouteTable", "TransitGateway":
		return domain.HopActionRouted
	case "ALB", "NLB", "CLB", "GWLB", "TargetGroup", "VPCLink":
		return domain.HopActionForwarded
	case "InternetGateway", "NATGateway", "VPNConnection", "DirectConnectGateway", "IPTarget", "LocalGateway", "CarrierGateway":
		return domain.HopActionTerminal
	default:
		return domain.HopActionEntered
	}
}

func inferLineage(source, target domain.Component) domain.HopLineage {
	sourceType := source.GetComponentType()
	targetType := target.GetComponentType()

	relationship := inferRelationship(sourceType, targetType)
	return domain.NewHopLineage(source.GetID(), sourceType, relationship)
}

func inferRelationship(sourceType, targetType string) string {
	switch sourceType {
	case "EC2Instance", "RDSInstance", "LambdaFunction", "EKSPod", "ElastiCacheCluster":
		switch targetType {
		case "SecurityGroup":
			return "attached-to"
		case "Subnet":
			return "located-in"
		}
	case "Subnet":
		switch targetType {
		case "NACL":
			return "associated-with"
		case "RouteTable":
			return "associated-with"
		}
	case "RouteTable":
		switch targetType {
		case "InternetGateway", "NATGateway", "TransitGatewayAttachment", "VPCEndpoint", "VPCPeering", "VirtualPrivateGateway", "LocalGateway", "CarrierGateway":
			return "routes-via"
		case "EC2Instance", "RDSInstance", "IPTarget", "NetworkInterface":
			return "resolved-to"
		}
	case "ALB", "NLB", "CLB", "GWLB":
		if targetType == "TargetGroup" {
			return "forwards-to"
		}
		if targetType == "SecurityGroup" {
			return "attached-to"
		}
	case "TargetGroup":
		return "targets"
	case "TransitGatewayAttachment":
		if targetType == "TransitGateway" {
			return "connects-to"
		}
	case "TransitGateway":
		return "routes-via"
	case "VPCPeering":
		if targetType == "RouteTable" {
			return "peers-to"
		}
	case "VPCEndpoint", "GWLBEndpoint":
		switch targetType {
		case "SecurityGroup":
			return "attached-to"
		case "Subnet":
			return "located-in"
		case "APIGateway":
			return "exposes"
		}
	case "APIGateway":
		if targetType == "VPCLink" || targetType == "VPCEndpoint" {
			return "integrates-via"
		}
	case "VPCLink":
		switch targetType {
		case "NLB", "ALB":
			return "targets"
		case "SecurityGroup":
			return "attached-to"
		case "Subnet":
			return "located-in"
		}
	case "VirtualPrivateGateway":
		if targetType == "VPNConnection" {
			return "connects-via"
		}
	case "DirectConnectOnPrem":
		if targetType == "DirectConnectGateway" {
			return "connects-via"
		}
	case "SecurityGroup":
		return "chains-to"
	case "NACL":
		if targetType == "RouteTable" {
			return "precedes"
		}
	}
	return "leads-to"
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

func TestReachabilityAllPaths(ctx context.Context, source, destination domain.Component, accountCtx domain.AccountContext) domain.AllPathsResult {
	return TestReachabilityAllPathsWithResolver(ctx, source, destination, accountCtx, nil)
}

func TestReachabilityAllPathsWithResolver(ctx context.Context, source, destination domain.Component, accountCtx domain.AccountContext, resolver domain.DestinationResolver) domain.AllPathsResult {
	if resolver == nil && accountCtx != nil {
		resolver = resolverpkg.NewResolver(accountCtx)
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
	forwardPaths := TraverseAllPaths(source, destTarget, destination.GetID(), sourceAnalyzer, resolver, domain.HopLineage{})

	destAnalyzer := NewAnalyzerContext(ctx, ctxWithResolver)
	returnPaths := TraverseAllPaths(destination, sourceTarget, source.GetID(), destAnalyzer, resolver, domain.HopLineage{})

	successfulForward := 0
	for _, p := range forwardPaths {
		if p.Success {
			successfulForward++
		}
	}

	successfulReturn := 0
	for _, p := range returnPaths {
		if p.Success {
			successfulReturn++
		}
	}

	return domain.AllPathsResult{
		ForwardPaths:           forwardPaths,
		ReturnPaths:            returnPaths,
		SuccessfulForwardPaths: successfulForward,
		SuccessfulReturnPaths:  successfulReturn,
		HasReachablePath:       successfulForward > 0 && successfulReturn > 0,
	}
}

func TraverseAllPaths(current domain.Component, destination domain.RoutingTarget, destinationID string, analyzerCtx domain.AnalyzerContext, resolver domain.DestinationResolver, lineage domain.HopLineage) []*domain.PathTrace {
	trace := domain.NewPathTrace()
	return traverseAllPathsRecursive(current, destination, destinationID, analyzerCtx, resolver, trace, lineage, make(map[string]bool))
}

func traverseAllPathsRecursive(current domain.Component, destination domain.RoutingTarget, destinationID string, analyzerCtx domain.AnalyzerContext, resolver domain.DestinationResolver, trace *domain.PathTrace, lineage domain.HopLineage, visited map[string]bool) []*domain.PathTrace {
	if visited[current.GetID()] {
		return nil
	}
	visited[current.GetID()] = true
	defer func() { visited[current.GetID()] = false }()

	action := inferHopAction(current)
	hop := domain.HopFromComponent(current, lineage, action, "")
	trace.AddHop(hop)

	nextHops, err := current.GetNextHops(destination, analyzerCtx)
	if err != nil {
		blockedTrace := trace.Clone()
		blockedTrace.MarkBlocked(err.Error())
		return []*domain.PathTrace{blockedTrace}
	}

	if IsDestinationReached(nextHops, destination, destinationID) {
		successTrace := trace.Clone()
		successTrace.LastHop().Action = domain.HopActionTerminal
		successTrace.LastHop().Details = "destination reached"
		successTrace.MarkSuccess()
		return []*domain.PathTrace{successTrace}
	}

	var unvisitedHops []domain.Component
	for _, hop := range nextHops {
		if !visited[hop.GetID()] {
			unvisitedHops = append(unvisitedHops, hop)
		}
	}

	if len(unvisitedHops) == 0 {
		if isTerminalComponent(current) && isExternalDestination(destination.IP) {
			successTrace := trace.Clone()
			successTrace.LastHop().Action = domain.HopActionTerminal
			successTrace.LastHop().Details = "external destination via terminal"
			successTrace.MarkSuccess()
			return []*domain.PathTrace{successTrace}
		}
		if isFilterComponent(current) {
			successTrace := trace.Clone()
			successTrace.LastHop().Details = "filter passed"
			successTrace.MarkSuccess()
			return []*domain.PathTrace{successTrace}
		}
		blockedTrace := trace.Clone()
		blockedTrace.MarkBlocked("no route to destination")
		return []*domain.PathTrace{blockedTrace}
	}

	var allPaths []*domain.PathTrace
	for _, nextHop := range unvisitedHops {
		nextLineage := inferLineage(current, nextHop)
		branchTrace := trace.Clone()
		branchPaths := traverseAllPathsRecursive(nextHop, destination, destinationID, analyzerCtx, resolver, branchTrace, nextLineage, visited)
		allPaths = append(allPaths, branchPaths...)
	}

	if len(allPaths) == 0 {
		blockedTrace := trace.Clone()
		blockedTrace.MarkBlocked("all paths blocked")
		return []*domain.PathTrace{blockedTrace}
	}

	return allPaths
}
