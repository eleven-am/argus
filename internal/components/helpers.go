package components

import (
	"net"
	"sort"
	"strings"

	"github.com/eleven-am/argus/internal/domain"
)

func IPMatchesCIDR(ip, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return network.Contains(parsedIP)
}

func CIDROverlaps(cidr1, cidr2 string) bool {
	_, net1, err1 := net.ParseCIDR(cidr1)
	_, net2, err2 := net.ParseCIDR(cidr2)
	if err1 != nil || err2 != nil {
		return false
	}
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}

func SortNACLRulesByNumber(rules []domain.NACLRule) []domain.NACLRule {
	sorted := make([]domain.NACLRule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].RuleNumber < sorted[j].RuleNumber
	})
	return sorted
}

func protocolMatches(ruleProtocol, destProtocol string) bool {
	rule := normalizeProtocol(ruleProtocol)
	dest := normalizeProtocol(destProtocol)
	if rule == "all" {
		return true
	}
	return rule == dest
}

func portInRange(port, fromPort, toPort int) bool {
	if fromPort == 0 && toPort == 0 {
		return true
	}
	if fromPort == -1 && toPort == -1 {
		return true
	}
	return port >= fromPort && port <= toPort
}

func isExternalIP(ip string) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return !isPrivateIP(parsed)
}

func isPrivateIP(ip net.IP) bool {
	for _, cidr := range privateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

var privateCIDRs []*net.IPNet

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
			privateCIDRs = append(privateCIDRs, cidr)
		}
	}
}

func normalizeProtocol(p string) string {
	switch p {
	case "", "-1", "all":
		return "all"
	case "6":
		return "tcp"
	case "17":
		return "udp"
	default:
		return strings.ToLower(p)
	}
}
