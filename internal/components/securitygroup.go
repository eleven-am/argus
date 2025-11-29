package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type SecurityGroup struct {
	data      *domain.SecurityGroupData
	accountID string
	next      domain.Component
}

func NewSecurityGroup(data *domain.SecurityGroupData, accountID string) *SecurityGroup {
	return &SecurityGroup{
		data:      data,
		accountID: accountID,
	}
}

func NewSecurityGroupWithNext(data *domain.SecurityGroupData, accountID string, next domain.Component) *SecurityGroup {
	return &SecurityGroup{
		data:      data,
		accountID: accountID,
		next:      next,
	}
}

func (sg *SecurityGroup) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if dest.Direction == "inbound" {
		if err := sg.EvaluateInbound(dest, analyzerCtx); err != nil {
			return nil, err
		}
	} else {
		if err := sg.EvaluateOutbound(dest, analyzerCtx); err != nil {
			return nil, err
		}
	}

	if sg.next != nil {
		return []domain.Component{sg.next}, nil
	}
	return []domain.Component{}, nil
}

func (sg *SecurityGroup) IsFilter() bool {
	return true
}

func (sg *SecurityGroup) EvaluateOutbound(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) error {
	for _, rule := range sg.data.OutboundRules {
		if sg.ruleAllows(rule, dest, analyzerCtx) {
			return nil
		}
	}
	return &domain.BlockingError{
		ComponentID: sg.GetID(),
		Reason:      fmt.Sprintf("no outbound rule allows %s:%d/%s", dest.IP, dest.Port, dest.Protocol),
	}
}

func (sg *SecurityGroup) EvaluateInbound(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) error {
	for _, rule := range sg.data.InboundRules {
		if sg.ruleAllows(rule, dest, analyzerCtx) {
			return nil
		}
	}
	return &domain.BlockingError{
		ComponentID: sg.GetID(),
		Reason:      fmt.Sprintf("no inbound rule allows %s:%d/%s", dest.IP, dest.Port, dest.Protocol),
	}
}

func (sg *SecurityGroup) ruleAllows(rule domain.SecurityGroupRule, dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) bool {
	if !protocolMatches(rule.Protocol, dest.Protocol) {
		return false
	}
	if !portInRange(dest.Port, rule.FromPort, rule.ToPort) {
		return false
	}

	for _, cidr := range rule.CIDRBlocks {
		if IPMatchesCIDR(dest.IP, cidr) {
			return true
		}
	}

	for _, cidr := range rule.IPv6CIDRBlocks {
		if IPMatchesCIDR(dest.IP, cidr) {
			return true
		}
	}

	for _, refSGID := range rule.ReferencedSecurityGroups {
		if sg.ipBelongsToSecurityGroup(dest.IP, refSGID, analyzerCtx) {
			return true
		}
	}

	for _, plID := range rule.PrefixListIDs {
		if sg.ipMatchesPrefixList(dest.IP, plID, analyzerCtx) {
			return true
		}
	}

	return false
}

func (sg *SecurityGroup) ipMatchesPrefixList(ip, plID string, analyzerCtx domain.AnalyzerContext) bool {
	if analyzerCtx == nil {
		return false
	}
	client, err := analyzerCtx.GetAccountContext().GetClient(sg.accountID)
	if err != nil {
		return false
	}
	pl, err := client.GetManagedPrefixList(analyzerCtx.Context(), plID)
	if err != nil {
		return false
	}
	for _, entry := range pl.Entries {
		if IPMatchesCIDR(ip, entry.CIDR) {
			return true
		}
	}
	return false
}

func (sg *SecurityGroup) ipBelongsToSecurityGroup(ip, sgID string, analyzerCtx domain.AnalyzerContext) bool {
	if analyzerCtx == nil {
		return false
	}
	client, err := analyzerCtx.GetAccountContext().GetClient(sg.accountID)
	if err != nil {
		return false
	}
	enis, err := client.GetENIsBySecurityGroup(analyzerCtx.Context(), sgID)
	if err != nil {
		return false
	}
	for _, eni := range enis {
		if eni.PrivateIP == ip {
			return true
		}
		for _, privateIP := range eni.PrivateIPs {
			if privateIP == ip {
				return true
			}
		}
	}
	return false
}

func (sg *SecurityGroup) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (sg *SecurityGroup) GetID() string {
	return fmt.Sprintf("%s:%s", sg.accountID, sg.data.ID)
}

func (sg *SecurityGroup) GetAccountID() string {
	return sg.accountID
}

func (sg *SecurityGroup) GetComponentType() string {
	return "SecurityGroup"
}
