package components

import (
	"encoding/json"
	"strings"
)

// policyAllows returns false only if an explicit Deny matches the destIP.
// It is a best-effort evaluator for VPC endpoint policies.
func policyAllows(destIP, policyJSON string) bool {
	if policyJSON == "" || destIP == "" {
		return true
	}
	var doc policyDocument
	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return true
	}

	// Denies take precedence
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "deny") {
			continue
		}
		ips := stmt.sourceIPs()
		for _, cidr := range ips {
			if IPMatchesCIDR(destIP, cidr) {
				return false
			}
		}
	}

	// If there are allows, require at least one match; otherwise default allow
	hasAllow := false
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "allow") {
			continue
		}
		hasAllow = true
		ips := stmt.sourceIPs()
		for _, cidr := range ips {
			if IPMatchesCIDR(destIP, cidr) {
				return true
			}
		}
	}
	if hasAllow {
		return false
	}
	return true
}

type policyDocument struct {
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect    string                 `json:"Effect"`
	Condition map[string]interface{} `json:"Condition"`
}

func (ps policyStatement) sourceIPs() []string {
	if ps.Condition == nil {
		return nil
	}
	var ips []string
	// Look for aws:SourceIp under any condition operator.
	for _, val := range ps.Condition {
		if m, ok := val.(map[string]interface{}); ok {
			if v, ok := m["aws:SourceIp"]; ok {
				switch t := v.(type) {
				case string:
					ips = append(ips, t)
				case []interface{}:
					for _, itm := range t {
						if s, ok := itm.(string); ok {
							ips = append(ips, s)
						}
					}
				}
			}
		}
	}

	return ips
}
