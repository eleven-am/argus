package components

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/eleven-am/argus/internal/domain"
)

type NetworkFirewall struct {
	data      *domain.NetworkFirewallData
	accountID string
}

func NewNetworkFirewall(data *domain.NetworkFirewallData, accountID string) *NetworkFirewall {
	return &NetworkFirewall{
		data:      data,
		accountID: accountID,
	}
}

func (nf *NetworkFirewall) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	statelessResult := nf.evaluateStatelessRules(dest)

	switch statelessResult.action {
	case "drop":
		return nil, &domain.BlockingError{
			ComponentID: nf.GetID(),
			Reason:      fmt.Sprintf("blocked by stateless rule: %s", statelessResult.reason),
		}
	case "pass":
		return nf.resolveNextHop(dest, analyzerCtx)
	case "forward_to_stateful":
		statefulResult := nf.evaluateStatefulRules(dest)
		if !statefulResult.allowed {
			return nil, &domain.BlockingError{
				ComponentID: nf.GetID(),
				Reason:      fmt.Sprintf("blocked by stateful rule: %s", statefulResult.reason),
			}
		}
		return nf.resolveNextHop(dest, analyzerCtx)
	}

	defaultAction := nf.getDefaultAction()
	if defaultAction == "drop" {
		return nil, &domain.BlockingError{
			ComponentID: nf.GetID(),
			Reason:      "blocked by default action",
		}
	}

	return nf.resolveNextHop(dest, analyzerCtx)
}

type statelessEvalResult struct {
	action string
	reason string
}

func (nf *NetworkFirewall) evaluateStatelessRules(dest domain.RoutingTarget) statelessEvalResult {
	groups := make([]domain.StatelessRuleGroup, len(nf.data.StatelessRuleGroups))
	copy(groups, nf.data.StatelessRuleGroups)
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Priority < groups[j].Priority
	})

	for _, group := range groups {
		rules := make([]domain.StatelessRule, len(group.Rules))
		copy(rules, group.Rules)
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Priority < rules[j].Priority
		})

		for _, rule := range rules {
			if nf.matchesStatelessRule(rule, dest) {
				action := nf.mapStatelessAction(rule.Actions)
				return statelessEvalResult{
					action: action,
					reason: fmt.Sprintf("matched stateless rule priority %d", rule.Priority),
				}
			}
		}
	}

	return statelessEvalResult{
		action: "forward_to_stateful",
		reason: "no stateless rule matched",
	}
}

func (nf *NetworkFirewall) matchesStatelessRule(rule domain.StatelessRule, dest domain.RoutingTarget) bool {
	if !nf.matchesProtocols(rule.Match.Protocols, dest.Protocol) {
		return false
	}

	if len(rule.Match.Destinations) > 0 {
		matched := false
		for _, cidr := range rule.Match.Destinations {
			if nf.matchesAddress(cidr, dest.IP) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(rule.Match.DestPorts) > 0 {
		matched := false
		for _, pr := range rule.Match.DestPorts {
			if pr.Contains(dest.Port) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

func (nf *NetworkFirewall) matchesProtocols(protocols []int, trafficProtocol string) bool {
	if len(protocols) == 0 {
		return true
	}

	protocolNum := nf.protocolToNumber(trafficProtocol)
	for _, p := range protocols {
		if p == protocolNum {
			return true
		}
	}
	return false
}

func (nf *NetworkFirewall) matchesAddress(addressDef string, ip string) bool {
	if addressDef == "ANY" || addressDef == "" {
		return true
	}

	if strings.Contains(addressDef, "/") {
		return IPMatchesCIDR(ip, addressDef)
	}

	return addressDef == ip
}

func (nf *NetworkFirewall) mapStatelessAction(actions []string) string {
	for _, action := range actions {
		switch strings.ToLower(action) {
		case "aws:drop":
			return "drop"
		case "aws:pass":
			return "pass"
		case "aws:forward_to_sfe":
			return "forward_to_stateful"
		}
	}
	return "forward_to_stateful"
}

func (nf *NetworkFirewall) protocolToNumber(protocol string) int {
	switch strings.ToLower(protocol) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "icmpv6":
		return 58
	default:
		p, _ := strconv.Atoi(protocol)
		return p
	}
}

type statefulEvalResult struct {
	allowed bool
	reason  string
}

func (nf *NetworkFirewall) evaluateStatefulRules(dest domain.RoutingTarget) statefulEvalResult {
	groups := make([]domain.StatefulRuleGroup, len(nf.data.StatefulRuleGroups))
	copy(groups, nf.data.StatefulRuleGroups)
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Priority < groups[j].Priority
	})

	for _, group := range groups {
		for _, rule := range group.Rules {
			if nf.matchesStatefulRule(rule, dest) {
				action := nf.mapStatefulAction(rule.Action)
				return statefulEvalResult{
					allowed: action == "pass",
					reason:  fmt.Sprintf("matched stateful rule action %s", rule.Action),
				}
			}
		}
	}

	defaultAction := nf.getStatefulDefaultAction()
	return statefulEvalResult{
		allowed: defaultAction != "drop",
		reason:  fmt.Sprintf("default stateful action: %s", defaultAction),
	}
}

func (nf *NetworkFirewall) matchesStatefulRule(rule domain.StatefulRule, dest domain.RoutingTarget) bool {
	if rule.Direction != "" && rule.Direction != dest.Direction {
		return false
	}

	if rule.Protocol != "any" && rule.Protocol != "" {
		if !protocolMatches(rule.Protocol, dest.Protocol) {
			return false
		}
	}

	if rule.Destination != "any" && rule.Destination != "" {
		if !nf.matchesAddress(rule.Destination, dest.IP) {
			return false
		}
	}

	if rule.DestPort != "any" && rule.DestPort != "" {
		port, err := strconv.Atoi(rule.DestPort)
		if err == nil && port != dest.Port {
			return false
		}
	}

	return true
}

func (nf *NetworkFirewall) mapStatefulAction(action string) string {
	switch strings.ToLower(action) {
	case "pass":
		return "pass"
	case "drop":
		return "drop"
	case "reject":
		return "drop"
	case "alert":
		return "pass"
	default:
		return "drop"
	}
}

func (nf *NetworkFirewall) getDefaultAction() string {
	if len(nf.data.DefaultActions.StatelessDefaultActions) > 0 {
		return nf.mapStatelessAction(nf.data.DefaultActions.StatelessDefaultActions)
	}
	return "forward_to_stateful"
}

func (nf *NetworkFirewall) getStatefulDefaultAction() string {
	if len(nf.data.DefaultActions.StatefulDefaultActions) > 0 {
		action := nf.data.DefaultActions.StatefulDefaultActions[0]
		if strings.Contains(strings.ToLower(action), "drop") {
			return "drop"
		}
	}
	return "pass"
}

func (nf *NetworkFirewall) resolveNextHop(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(nf.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	for _, mapping := range nf.data.SubnetMappings {
		subnetData, err := client.GetSubnet(ctx, mapping.SubnetID)
		if err != nil {
			continue
		}
		if IPMatchesCIDR(dest.IP, subnetData.CIDRBlock) {
			rtData, err := client.GetRouteTable(ctx, subnetData.RouteTableID)
			if err != nil {
				return nil, err
			}
			return []domain.Component{NewRouteTable(rtData, nf.accountID)}, nil
		}
	}

	vpcData, err := client.GetVPC(ctx, nf.data.VPCID)
	if err != nil {
		return nil, err
	}

	rtData, err := client.GetRouteTable(ctx, vpcData.MainRouteTableID)
	if err != nil {
		return nil, err
	}

	return []domain.Component{NewRouteTable(rtData, nf.accountID)}, nil
}

func (nf *NetworkFirewall) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (nf *NetworkFirewall) GetID() string {
	return fmt.Sprintf("%s:%s", nf.accountID, nf.data.ID)
}

func (nf *NetworkFirewall) GetAccountID() string {
	return nf.accountID
}

func (nf *NetworkFirewall) GetComponentType() string {
	return "NetworkFirewall"
}

func (nf *NetworkFirewall) GetVPCID() string {
	return nf.data.VPCID
}

func (nf *NetworkFirewall) GetRegion() string {
	return ""
}

func (nf *NetworkFirewall) GetSubnetID() string {
	if len(nf.data.SubnetMappings) > 0 {
		return nf.data.SubnetMappings[0].SubnetID
	}
	return ""
}

func (nf *NetworkFirewall) GetAvailabilityZone() string {
	return ""
}

func (nf *NetworkFirewall) EvaluateWithDetails(target domain.RoutingTarget, direction string) domain.EvaluationResult {
	var evaluations []domain.RuleEvaluation

	for _, group := range nf.data.StatelessRuleGroups {
		for i, rule := range group.Rules {
			eval := domain.RuleEvaluation{
				RuleID:   fmt.Sprintf("stateless-group-%d-rule-%d", group.Priority, i),
				RuleType: "NetworkFirewall-Stateless",
				Priority: rule.Priority,
				Action:   nf.mapStatelessAction(rule.Actions),
			}

			if len(rule.Match.DestPorts) > 0 {
				eval.PortFrom = rule.Match.DestPorts[0].From
				eval.PortTo = rule.Match.DestPorts[0].To
			}

			if nf.matchesStatelessRule(rule, target) {
				eval.Matched = true
				eval.Reason = "matched stateless rule"
				evaluations = append(evaluations, eval)

				action := nf.mapStatelessAction(rule.Actions)
				if action == "pass" {
					return domain.EvaluationResult{
						Allowed:     true,
						Reason:      fmt.Sprintf("allowed by stateless rule %d", rule.Priority),
						Evaluations: evaluations,
					}
				} else if action == "drop" {
					return domain.EvaluationResult{
						Allowed:     false,
						Reason:      fmt.Sprintf("blocked by stateless rule %d", rule.Priority),
						Evaluations: evaluations,
					}
				}
			} else {
				eval.Matched = false
				eval.Reason = "no match"
				evaluations = append(evaluations, eval)
			}
		}
	}

	for _, group := range nf.data.StatefulRuleGroups {
		for i, rule := range group.Rules {
			eval := domain.RuleEvaluation{
				RuleID:   fmt.Sprintf("stateful-group-%d-rule-%d", group.Priority, i),
				RuleType: "NetworkFirewall-Stateful",
				Priority: group.Priority,
				Protocol: rule.Protocol,
				Action:   nf.mapStatefulAction(rule.Action),
			}

			if nf.matchesStatefulRule(rule, target) {
				eval.Matched = true
				eval.Reason = "matched stateful rule"
				evaluations = append(evaluations, eval)

				action := nf.mapStatefulAction(rule.Action)
				return domain.EvaluationResult{
					Allowed:     action == "pass",
					Reason:      fmt.Sprintf("stateful rule action: %s", rule.Action),
					Evaluations: evaluations,
				}
			} else {
				eval.Matched = false
				eval.Reason = "no match"
				evaluations = append(evaluations, eval)
			}
		}
	}

	defaultAction := nf.getStatefulDefaultAction()
	return domain.EvaluationResult{
		Allowed:     defaultAction != "drop",
		Reason:      fmt.Sprintf("default action: %s", defaultAction),
		Evaluations: evaluations,
	}
}

type NetworkFirewallEndpoint struct {
	firewallID string
	endpointID string
	subnetID   string
	accountID  string
}

func NewNetworkFirewallEndpoint(firewallID, endpointID, subnetID, accountID string) *NetworkFirewallEndpoint {
	return &NetworkFirewallEndpoint{
		firewallID: firewallID,
		endpointID: endpointID,
		subnetID:   subnetID,
		accountID:  accountID,
	}
}

func (nfe *NetworkFirewallEndpoint) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(nfe.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	firewallData, err := client.GetNetworkFirewall(ctx, nfe.firewallID)
	if err != nil {
		return nil, err
	}

	return []domain.Component{NewNetworkFirewall(firewallData, nfe.accountID)}, nil
}

func (nfe *NetworkFirewallEndpoint) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (nfe *NetworkFirewallEndpoint) GetID() string {
	return fmt.Sprintf("%s:%s", nfe.accountID, nfe.endpointID)
}

func (nfe *NetworkFirewallEndpoint) GetAccountID() string {
	return nfe.accountID
}

func (nfe *NetworkFirewallEndpoint) GetComponentType() string {
	return "NetworkFirewallEndpoint"
}

func (nfe *NetworkFirewallEndpoint) GetVPCID() string {
	return ""
}

func (nfe *NetworkFirewallEndpoint) GetRegion() string {
	return ""
}

func (nfe *NetworkFirewallEndpoint) GetSubnetID() string {
	return nfe.subnetID
}

func (nfe *NetworkFirewallEndpoint) GetAvailabilityZone() string {
	return ""
}
