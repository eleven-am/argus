package domain

type NetworkFirewallData struct {
	ID                  string
	Name                string
	PolicyARN           string
	VPCID               string
	SubnetMappings      []FirewallSubnetMapping
	StatelessRuleGroups []StatelessRuleGroup
	StatefulRuleGroups  []StatefulRuleGroup
	DefaultActions      FirewallDefaultActions
}

type FirewallSubnetMapping struct {
	SubnetID   string
	EndpointID string
}

type FirewallDefaultActions struct {
	StatelessDefaultActions         []string
	StatelessFragmentDefaultActions []string
	StatefulDefaultActions          []string
}

type StatelessRuleGroup struct {
	Priority int
	ARN      string
	Rules    []StatelessRule
}

type StatelessRule struct {
	Priority int
	Actions  []string
	Match    StatelessMatch
}

type StatelessMatch struct {
	Protocols    []int
	Sources      []string
	Destinations []string
	SourcePorts  []PortRangeSpec
	DestPorts    []PortRangeSpec
	TCPFlags     []TCPFlagSpec
}

type PortRangeSpec struct {
	From int
	To   int
}

type TCPFlagSpec struct {
	Flags []string
	Masks []string
}

type StatefulRuleGroup struct {
	Priority  int
	ARN       string
	RuleOrder string
	Rules     []StatefulRule
}

type StatefulRule struct {
	Action      string
	Protocol    string
	Source      string
	SourcePort  string
	Destination string
	DestPort    string
	Direction   string
	SID         string
}

func (p PortRangeSpec) Contains(port int) bool {
	if p.From == 0 && p.To == 0 {
		return true
	}
	return port >= p.From && port <= p.To
}
