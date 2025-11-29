package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type NACL struct {
	data      *domain.NACLData
	accountID string
	next      domain.Component
}

func NewNACL(data *domain.NACLData, accountID string) *NACL {
	return &NACL{
		data:      data,
		accountID: accountID,
	}
}

func NewNACLWithNext(data *domain.NACLData, accountID string, next domain.Component) *NACL {
	return &NACL{
		data:      data,
		accountID: accountID,
		next:      next,
	}
}

func (n *NACL) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if dest.Direction == "inbound" {
		if err := n.EvaluateInbound(dest, analyzerCtx); err != nil {
			return nil, err
		}
	} else {
		if err := n.EvaluateOutbound(dest, analyzerCtx); err != nil {
			return nil, err
		}
	}

	if n.next != nil {
		return []domain.Component{n.next}, nil
	}
	return []domain.Component{}, nil
}

func (n *NACL) IsFilter() bool {
	return true
}

func (n *NACL) EvaluateOutbound(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) error {
	sortedRules := SortNACLRulesByNumber(n.data.OutboundRules)

	for _, rule := range sortedRules {
		if n.ruleMatches(rule, dest) {
			if rule.Action == "allow" {
				return nil
			}
			return &domain.BlockingError{
				ComponentID: n.GetID(),
				Reason:      fmt.Sprintf("NACL outbound rule %d denies traffic to %s:%d/%s", rule.RuleNumber, dest.IP, dest.Port, dest.Protocol),
			}
		}
	}

	return &domain.BlockingError{
		ComponentID: n.GetID(),
		Reason:      "no outbound NACL rule matches, implicit deny",
	}
}

func (n *NACL) EvaluateInbound(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) error {
	sortedRules := SortNACLRulesByNumber(n.data.InboundRules)

	for _, rule := range sortedRules {
		if n.ruleMatches(rule, dest) {
			if rule.Action == "allow" {
				return nil
			}
			return &domain.BlockingError{
				ComponentID: n.GetID(),
				Reason:      fmt.Sprintf("NACL inbound rule %d denies traffic to %s:%d/%s", rule.RuleNumber, dest.IP, dest.Port, dest.Protocol),
			}
		}
	}

	return &domain.BlockingError{
		ComponentID: n.GetID(),
		Reason:      "no inbound NACL rule matches, implicit deny",
	}
}

func (n *NACL) ruleMatches(rule domain.NACLRule, target domain.RoutingTarget) bool {
	if !protocolMatches(rule.Protocol, target.Protocol) {
		return false
	}
	if !portInRange(target.Port, rule.FromPort, rule.ToPort) {
		return false
	}
	if rule.CIDRBlock != "" && IPMatchesCIDR(target.IP, rule.CIDRBlock) {
		return true
	}
	if rule.IPv6CIDRBlock != "" && IPMatchesCIDR(target.IP, rule.IPv6CIDRBlock) {
		return true
	}
	return false
}

func (n *NACL) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (n *NACL) GetID() string {
	return fmt.Sprintf("%s:%s", n.accountID, n.data.ID)
}

func (n *NACL) GetAccountID() string {
	return n.accountID
}

func (n *NACL) GetComponentType() string {
	return "NACL"
}

func (n *NACL) GetVPCID() string {
	return n.data.VPCID
}

func (n *NACL) GetRegion() string {
	return ""
}

func (n *NACL) GetSubnetID() string {
	return ""
}

func (n *NACL) GetAvailabilityZone() string {
	return ""
}

func (n *NACL) EvaluateWithDetails(target domain.RoutingTarget, direction string) domain.EvaluationResult {
	var rules []domain.NACLRule
	ruleType := "outbound"
	if direction == "inbound" {
		rules = SortNACLRulesByNumber(n.data.InboundRules)
		ruleType = "inbound"
	} else {
		rules = SortNACLRulesByNumber(n.data.OutboundRules)
	}

	var evaluations []domain.RuleEvaluation

	for _, rule := range rules {
		eval := domain.RuleEvaluation{
			RuleID:   fmt.Sprintf("%s-rule-%d", ruleType, rule.RuleNumber),
			RuleType: "NACL",
			Protocol: rule.Protocol,
			PortFrom: rule.FromPort,
			PortTo:   rule.ToPort,
			Priority: rule.RuleNumber,
			Action:   rule.Action,
		}

		if rule.CIDRBlock != "" {
			eval.DestCIDR = rule.CIDRBlock
		} else if rule.IPv6CIDRBlock != "" {
			eval.DestCIDR = rule.IPv6CIDRBlock
		}

		protocolMatch := protocolMatches(rule.Protocol, target.Protocol)
		portMatch := portInRange(target.Port, rule.FromPort, rule.ToPort)

		if !protocolMatch {
			eval.Matched = false
			eval.Reason = fmt.Sprintf("protocol mismatch: rule=%s target=%s", rule.Protocol, target.Protocol)
			evaluations = append(evaluations, eval)
			continue
		}

		if !portMatch {
			eval.Matched = false
			eval.Reason = fmt.Sprintf("port %d not in range %d-%d", target.Port, rule.FromPort, rule.ToPort)
			evaluations = append(evaluations, eval)
			continue
		}

		cidrMatch := false
		if rule.CIDRBlock != "" && IPMatchesCIDR(target.IP, rule.CIDRBlock) {
			cidrMatch = true
			eval.DestCIDR = rule.CIDRBlock
		}
		if !cidrMatch && rule.IPv6CIDRBlock != "" && IPMatchesCIDR(target.IP, rule.IPv6CIDRBlock) {
			cidrMatch = true
			eval.DestCIDR = rule.IPv6CIDRBlock
		}

		if cidrMatch {
			eval.Matched = true
			eval.Reason = "CIDR match"
			evaluations = append(evaluations, eval)

			if rule.Action == "allow" {
				return domain.EvaluationResult{
					Allowed:     true,
					Reason:      fmt.Sprintf("allowed by NACL rule %d", rule.RuleNumber),
					Evaluations: evaluations,
				}
			}
			return domain.EvaluationResult{
				Allowed:     false,
				Reason:      fmt.Sprintf("denied by NACL rule %d", rule.RuleNumber),
				Evaluations: evaluations,
			}
		}

		eval.Matched = false
		eval.Reason = fmt.Sprintf("IP %s not in CIDR %s", target.IP, eval.DestCIDR)
		evaluations = append(evaluations, eval)
	}

	return domain.EvaluationResult{
		Allowed:     false,
		Reason:      fmt.Sprintf("no %s NACL rule matches, implicit deny", ruleType),
		Evaluations: evaluations,
	}
}
