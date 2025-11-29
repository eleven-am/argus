package domain

type SecurityGroupData struct {
	ID            string
	VPCID         string
	InboundRules  []SecurityGroupRule
	OutboundRules []SecurityGroupRule
}

type SecurityGroupRule struct {
	Protocol                 string
	FromPort                 int
	ToPort                   int
	CIDRBlocks               []string
	IPv6CIDRBlocks           []string
	ReferencedSecurityGroups []string
	PrefixListIDs            []string
}

type SubnetData struct {
	ID            string
	VPCID         string
	CIDRBlock     string
	IPv6CIDRBlock string
	NaclID        string
	RouteTableID  string
}

type NACLData struct {
	ID            string
	VPCID         string
	InboundRules  []NACLRule
	OutboundRules []NACLRule
}

type NACLRule struct {
	RuleNumber    int
	Protocol      string
	FromPort      int
	ToPort        int
	CIDRBlock     string
	IPv6CIDRBlock string
	Action        string
}

type RouteTableData struct {
	ID     string
	VPCID  string
	Routes []Route
}

type Route struct {
	DestinationCIDR         string
	DestinationIPv6CIDR     string
	DestinationPrefixListID string
	PrefixLength            int
	TargetType              string
	TargetID                string
}

type VPCData struct {
	ID               string
	CIDRBlock        string
	IPv6CIDRBlock    string
	MainRouteTableID string
}

type TGWRouteAttachment struct {
	ID         string
	Type       string
	ResourceID string
	OwnerID    string
	State      string
}

type TGWRoute struct {
	DestinationCIDR string
	PrefixLength    int
	State           string
	Attachments     []TGWRouteAttachment
}

type TGWRouteTableAssociation struct {
	AttachmentID string
	ResourceType string
	State        string
}

type TGWRouteTablePropagation struct {
	AttachmentID string
	ResourceType string
	State        string
}

type TGWRouteTableData struct {
	ID           string
	Routes       []TGWRoute
	Associations []TGWRouteTableAssociation
	Propagations []TGWRouteTablePropagation
}

type TransitGatewayData struct {
	ID          string
	OwnerID     string
	RouteTables []TGWRouteTableData
}

type TGWAttachmentData struct {
	ID                      string
	TransitGatewayID        string
	TGWAccountID            string
	VPCID                   string
	SubnetIDs               []string
	State                   string
	PropagatedRouteTableIDs []string
}

type EC2InstanceData struct {
	ID             string
	PrivateIP      string
	SecurityGroups []string
	SubnetID       string
}

type RDSInstanceData struct {
	ID             string
	Endpoint       string
	PrivateIP      string
	Port           int
	SecurityGroups []string
	SubnetIDs      []string
}

type LambdaFunctionData struct {
	Name           string
	VPCID          string
	SubnetIDs      []string
	SubnetCIDRs    []string
	SecurityGroups []string
	ENIIPs         []string
}

type InternetGatewayData struct {
	ID    string
	VPCID string
}

type NATGatewayData struct {
	ID       string
	SubnetID string
	PublicIP string
}

type VPCEndpointData struct {
	ID             string
	VPCID          string
	ServiceName    string
	Type           string
	State          string
	SubnetIDs      []string
	SecurityGroups []string
	PolicyJSON     string
}

type VPCPeeringData struct {
	ID             string
	RequesterVPC   string
	RequesterOwner string
	AccepterVPC    string
	AccepterOwner  string
	Status         string
}

type VirtualPrivateGatewayData struct {
	ID    string
	VPCID string
}

type VPNConnectionData struct {
	ID          string
	VGWID       string
	State       string
	HasUpTunnel bool
}

type DirectConnectGatewayData struct {
	ID              string
	OwnerID         string
	State           string
	AllowedPrefixes []string
}

type TGWPeeringAttachmentData struct {
	ID                   string
	TransitGatewayID     string
	PeerTransitGatewayID string
	PeerAccountID        string
}

type ENIData struct {
	ID             string
	PrivateIP      string
	PrivateIPs     []string
	SubnetID       string
	SecurityGroups []string
}

type ManagedPrefixListData struct {
	ID      string
	Name    string
	Entries []PrefixListEntry
}

type PrefixListEntry struct {
	CIDR        string
	Description string
}

type ALBData struct {
	ARN             string
	DNSName         string
	Scheme          string
	VPCID           string
	SubnetIDs       []string
	SecurityGroups  []string
	TargetGroupARNs []string
	FrontendIPs     []string
}

type NLBData struct {
	ARN             string
	DNSName         string
	Scheme          string
	VPCID           string
	SubnetIDs       []string
	SecurityGroups  []string
	TargetGroupARNs []string
	FrontendIPs     []string
}

type GWLBData struct {
	ARN             string
	DNSName         string
	VPCID           string
	SubnetIDs       []string
	TargetGroupARNs []string
}

type CLBData struct {
	Name           string
	DNSName        string
	Scheme         string
	VPCID          string
	SubnetIDs      []string
	SecurityGroups []string
	InstanceIDs    []string
	FrontendIPs    []string
}

type TargetGroupData struct {
	ARN        string
	Name       string
	TargetType string
	Protocol   string
	Port       int
	VPCID      string
	Targets    []TargetData
}

type TargetData struct {
	ID           string
	Port         int
	HealthStatus string
}

type IPTargetData struct {
	IP   string
	Port int
}

type APIGatewayData struct {
	ID             string
	Name           string
	APIType        string
	EndpointType   string
	VPCEndpointIDs []string
	VPCLinkIDs     []string
	PrivateIPs     []string
}

type VPCLinkData struct {
	ID                 string
	Name               string
	Version            string
	TargetARNs         []string
	VPCID              string
	SubnetIDs          []string
	SecurityGroups     []string
	Status             string
	IntegrationTargets []string
}

type EKSPodData struct {
	PodName        string
	Namespace      string
	PodIP          string
	HostIP         string
	NodeName       string
	ENIID          string
	SecurityGroups []string
	SubnetID       string
}

type ElastiCacheClusterData struct {
	ID             string
	Engine         string
	EngineVersion  string
	NodeType       string
	NumNodes       int
	Port           int
	Nodes          []ElastiCacheNodeData
	SecurityGroups []string
	SubnetIDs      []string
	VPCID          string
}

type ElastiCacheNodeData struct {
	ID        string
	Endpoint  string
	PrivateIP string
	Port      int
}

type DirectConnectOnPremData struct {
	OnPremCIDR      string
	SourceIP        string
	DXGWID          string
	TGWAttachmentID string
	AllowedPrefixes []string
	AttachmentState string
}
