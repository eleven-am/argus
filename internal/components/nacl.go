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
