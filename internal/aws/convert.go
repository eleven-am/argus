package aws

import (
	"net"
	"strconv"
	"strings"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/eleven-am/argus/internal/domain"
)

func toSecurityGroupData(sg *ec2types.SecurityGroup) *domain.SecurityGroupData {
	return &domain.SecurityGroupData{
		ID:            derefString(sg.GroupId),
		VPCID:         derefString(sg.VpcId),
		InboundRules:  toSecurityGroupRules(sg.IpPermissions),
		OutboundRules: toSecurityGroupRules(sg.IpPermissionsEgress),
	}
}

func toSecurityGroupRules(perms []ec2types.IpPermission) []domain.SecurityGroupRule {
	var rules []domain.SecurityGroupRule
	for _, perm := range perms {
		var ipv4Cidrs []string
		for _, r := range perm.IpRanges {
			if r.CidrIp != nil {
				ipv4Cidrs = append(ipv4Cidrs, *r.CidrIp)
			}
		}

		var ipv6Cidrs []string
		for _, r := range perm.Ipv6Ranges {
			if r.CidrIpv6 != nil {
				ipv6Cidrs = append(ipv6Cidrs, *r.CidrIpv6)
			}
		}

		var referencedSGs []string
		for _, pair := range perm.UserIdGroupPairs {
			if pair.GroupId != nil {
				referencedSGs = append(referencedSGs, *pair.GroupId)
			}
		}

		var prefixListIDs []string
		for _, pl := range perm.PrefixListIds {
			if pl.PrefixListId != nil {
				prefixListIDs = append(prefixListIDs, *pl.PrefixListId)
			}
		}

		protocol := derefString(perm.IpProtocol)
		if protocol == "-1" {
			protocol = "-1"
		}

		rules = append(rules, domain.SecurityGroupRule{
			Protocol:                 protocol,
			FromPort:                 int(derefInt32(perm.FromPort)),
			ToPort:                   int(derefInt32(perm.ToPort)),
			CIDRBlocks:               ipv4Cidrs,
			IPv6CIDRBlocks:           ipv6Cidrs,
			ReferencedSecurityGroups: referencedSGs,
			PrefixListIDs:            prefixListIDs,
		})
	}
	return rules
}

func toSubnetData(subnet *ec2types.Subnet, naclID, rtID string) *domain.SubnetData {
	var ipv6CIDR string
	for _, assoc := range subnet.Ipv6CidrBlockAssociationSet {
		if assoc.Ipv6CidrBlock != nil {
			ipv6CIDR = *assoc.Ipv6CidrBlock
			break
		}
	}
	return &domain.SubnetData{
		ID:            derefString(subnet.SubnetId),
		VPCID:         derefString(subnet.VpcId),
		CIDRBlock:     derefString(subnet.CidrBlock),
		IPv6CIDRBlock: ipv6CIDR,
		NaclID:        naclID,
		RouteTableID:  rtID,
	}
}

func toNACLData(nacl *ec2types.NetworkAcl) *domain.NACLData {
	var inbound, outbound []domain.NACLRule
	for _, entry := range nacl.Entries {
		rule := domain.NACLRule{
			RuleNumber:    int(derefInt32(entry.RuleNumber)),
			Protocol:      protocolNumberToString(derefString(entry.Protocol)),
			CIDRBlock:     derefString(entry.CidrBlock),
			IPv6CIDRBlock: derefString(entry.Ipv6CidrBlock),
			Action:        string(entry.RuleAction),
		}
		if entry.PortRange != nil {
			rule.FromPort = int(derefInt32(entry.PortRange.From))
			rule.ToPort = int(derefInt32(entry.PortRange.To))
		}
		if entry.Egress != nil && *entry.Egress {
			outbound = append(outbound, rule)
		} else {
			inbound = append(inbound, rule)
		}
	}
	return &domain.NACLData{
		ID:            derefString(nacl.NetworkAclId),
		VPCID:         derefString(nacl.VpcId),
		InboundRules:  inbound,
		OutboundRules: outbound,
	}
}

func toRouteTableData(rt *ec2types.RouteTable) *domain.RouteTableData {
	var routes []domain.Route
	for _, r := range rt.Routes {
		route := domain.Route{
			DestinationCIDR:         derefString(r.DestinationCidrBlock),
			DestinationIPv6CIDR:     derefString(r.DestinationIpv6CidrBlock),
			DestinationPrefixListID: derefString(r.DestinationPrefixListId),
		}

		if route.DestinationCIDR != "" {
			route.PrefixLength = prefixLength(route.DestinationCIDR)
		} else if route.DestinationIPv6CIDR != "" {
			route.PrefixLength = prefixLength(route.DestinationIPv6CIDR)
		}

		route.TargetType, route.TargetID = determineRouteTarget(r)
		routes = append(routes, route)
	}
	return &domain.RouteTableData{
		ID:     derefString(rt.RouteTableId),
		VPCID:  derefString(rt.VpcId),
		Routes: routes,
	}
}

func determineRouteTarget(r ec2types.Route) (targetType, targetID string) {
	switch {
	case r.GatewayId != nil && strings.HasPrefix(*r.GatewayId, "igw-"):
		return "internet-gateway", *r.GatewayId
	case r.GatewayId != nil && strings.HasPrefix(*r.GatewayId, "vgw-"):
		return "vpn-gateway", *r.GatewayId
	case r.GatewayId != nil && strings.HasPrefix(*r.GatewayId, "vpce-"):
		return "vpc-endpoint", *r.GatewayId
	case r.GatewayId != nil && *r.GatewayId == "local":
		return "local", "local"
	case r.NatGatewayId != nil:
		return "nat-gateway", *r.NatGatewayId
	case r.TransitGatewayId != nil:
		return "transit-gateway", *r.TransitGatewayId
	case r.VpcPeeringConnectionId != nil:
		return "vpc-peering", *r.VpcPeeringConnectionId
	case r.NetworkInterfaceId != nil:
		return "network-interface", *r.NetworkInterfaceId
	case r.LocalGatewayId != nil:
		return "local-gateway", *r.LocalGatewayId
	case r.CarrierGatewayId != nil:
		return "carrier-gateway", *r.CarrierGatewayId
	default:
		return "unknown", ""
	}
}

func toVPCData(vpc *ec2types.Vpc, mainRtID string) *domain.VPCData {
	var ipv6CIDR string
	for _, assoc := range vpc.Ipv6CidrBlockAssociationSet {
		if assoc.Ipv6CidrBlock != nil {
			ipv6CIDR = *assoc.Ipv6CidrBlock
			break
		}
	}
	return &domain.VPCData{
		ID:               derefString(vpc.VpcId),
		CIDRBlock:        derefString(vpc.CidrBlock),
		IPv6CIDRBlock:    ipv6CIDR,
		MainRouteTableID: mainRtID,
	}
}

func toTransitGatewayData(tgw *ec2types.TransitGateway, rts []domain.TGWRouteTableData) *domain.TransitGatewayData {
	return &domain.TransitGatewayData{
		ID:          derefString(tgw.TransitGatewayId),
		OwnerID:     derefString(tgw.OwnerId),
		RouteTables: rts,
	}
}

func toTGWAttachmentData(att *ec2types.TransitGatewayVpcAttachment, tgwOwnerID, state string, propagatedRTIDs []string) *domain.TGWAttachmentData {
	var subnets []string
	for _, s := range att.SubnetIds {
		subnets = append(subnets, s)
	}

	accountID := tgwOwnerID
	if accountID == "" {
		accountID = derefString(att.VpcOwnerId)
	}

	return &domain.TGWAttachmentData{
		ID:                      derefString(att.TransitGatewayAttachmentId),
		TransitGatewayID:        derefString(att.TransitGatewayId),
		TGWAccountID:            accountID,
		VPCID:                   derefString(att.VpcId),
		SubnetIDs:               subnets,
		State:                   state,
		PropagatedRouteTableIDs: propagatedRTIDs,
	}
}

func toEC2InstanceData(inst *ec2types.Instance) *domain.EC2InstanceData {
	var sgs []string
	for _, sg := range inst.SecurityGroups {
		if sg.GroupId != nil {
			sgs = append(sgs, *sg.GroupId)
		}
	}
	return &domain.EC2InstanceData{
		ID:             derefString(inst.InstanceId),
		PrivateIP:      derefString(inst.PrivateIpAddress),
		SecurityGroups: sgs,
		SubnetID:       derefString(inst.SubnetId),
	}
}

func toRDSInstanceData(db *rdstypes.DBInstance, privateIP string) *domain.RDSInstanceData {
	var sgs []string
	for _, sg := range db.VpcSecurityGroups {
		if sg.VpcSecurityGroupId != nil {
			sgs = append(sgs, *sg.VpcSecurityGroupId)
		}
	}
	var subnets []string
	if db.DBSubnetGroup != nil {
		for _, subnet := range db.DBSubnetGroup.Subnets {
			if subnet.SubnetIdentifier != nil {
				subnets = append(subnets, *subnet.SubnetIdentifier)
			}
		}
	}

	endpoint := ""
	port := 0
	if db.Endpoint != nil {
		endpoint = derefString(db.Endpoint.Address)
		port = int(derefInt32(db.Endpoint.Port))
	}

	return &domain.RDSInstanceData{
		ID:             derefString(db.DBInstanceIdentifier),
		Endpoint:       endpoint,
		PrivateIP:      privateIP,
		Port:           port,
		SecurityGroups: sgs,
		SubnetIDs:      subnets,
	}
}

func toLambdaFunctionData(fn *lambda.GetFunctionOutput) *domain.LambdaFunctionData {
	data := &domain.LambdaFunctionData{
		Name: derefString(fn.Configuration.FunctionName),
	}
	if fn.Configuration.VpcConfig != nil {
		data.VPCID = derefString(fn.Configuration.VpcConfig.VpcId)
		data.SubnetIDs = fn.Configuration.VpcConfig.SubnetIds
		data.SecurityGroups = fn.Configuration.VpcConfig.SecurityGroupIds
	}
	return data
}

func toInternetGatewayData(igw *ec2types.InternetGateway) *domain.InternetGatewayData {
	var vpcID string
	if len(igw.Attachments) > 0 {
		vpcID = derefString(igw.Attachments[0].VpcId)
	}
	return &domain.InternetGatewayData{
		ID:    derefString(igw.InternetGatewayId),
		VPCID: vpcID,
	}
}

func toNATGatewayData(nat *ec2types.NatGateway) *domain.NATGatewayData {
	var publicIP string
	for _, addr := range nat.NatGatewayAddresses {
		if addr.PublicIp != nil {
			publicIP = *addr.PublicIp
			break
		}
	}
	return &domain.NATGatewayData{
		ID:       derefString(nat.NatGatewayId),
		SubnetID: derefString(nat.SubnetId),
		PublicIP: publicIP,
	}
}

func toVPCEndpointData(ep *ec2types.VpcEndpoint) *domain.VPCEndpointData {
	var subnetIDs []string
	for _, id := range ep.SubnetIds {
		subnetIDs = append(subnetIDs, id)
	}
	var sgIDs []string
	for _, sg := range ep.Groups {
		sgIDs = append(sgIDs, derefString(sg.GroupId))
	}
	return &domain.VPCEndpointData{
		ID:             derefString(ep.VpcEndpointId),
		VPCID:          derefString(ep.VpcId),
		ServiceName:    derefString(ep.ServiceName),
		Type:           string(ep.VpcEndpointType),
		State:          string(ep.State),
		SubnetIDs:      subnetIDs,
		SecurityGroups: sgIDs,
		PolicyJSON:     derefString(ep.PolicyDocument),
	}
}

func toVPCPeeringData(pcx *ec2types.VpcPeeringConnection) *domain.VPCPeeringData {
	data := &domain.VPCPeeringData{
		ID: derefString(pcx.VpcPeeringConnectionId),
	}
	if pcx.RequesterVpcInfo != nil {
		data.RequesterVPC = derefString(pcx.RequesterVpcInfo.VpcId)
		data.RequesterOwner = derefString(pcx.RequesterVpcInfo.OwnerId)
	}
	if pcx.AccepterVpcInfo != nil {
		data.AccepterVPC = derefString(pcx.AccepterVpcInfo.VpcId)
		data.AccepterOwner = derefString(pcx.AccepterVpcInfo.OwnerId)
	}
	if pcx.Status != nil {
		data.Status = string(pcx.Status.Code)
	}
	return data
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt32(i *int32) int32 {
	if i == nil {
		return 0
	}
	return *i
}

func prefixLength(cidr string) int {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return 0
	}
	length, _ := strconv.Atoi(parts[1])
	return length
}

func protocolNumberToString(proto string) string {
	switch proto {
	case "-1":
		return "-1"
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	default:
		return proto
	}
}

func toALBData(lb *elbv2types.LoadBalancer, tgARNs []string) *domain.ALBData {
	var subnets []string
	for _, az := range lb.AvailabilityZones {
		if az.SubnetId != nil {
			subnets = append(subnets, *az.SubnetId)
		}
	}
	var sgs []string
	for _, sg := range lb.SecurityGroups {
		sgs = append(sgs, sg)
	}
	return &domain.ALBData{
		ARN:             derefString(lb.LoadBalancerArn),
		DNSName:         derefString(lb.DNSName),
		Scheme:          string(lb.Scheme),
		VPCID:           derefString(lb.VpcId),
		SubnetIDs:       subnets,
		SecurityGroups:  sgs,
		TargetGroupARNs: tgARNs,
		FrontendIPs:     nil, // not available via API
	}
}

func toNLBData(lb *elbv2types.LoadBalancer, tgARNs []string) *domain.NLBData {
	var subnets []string
	for _, az := range lb.AvailabilityZones {
		if az.SubnetId != nil {
			subnets = append(subnets, *az.SubnetId)
		}
	}
	var sgs []string
	for _, sg := range lb.SecurityGroups {
		sgs = append(sgs, sg)
	}
	return &domain.NLBData{
		ARN:             derefString(lb.LoadBalancerArn),
		DNSName:         derefString(lb.DNSName),
		Scheme:          string(lb.Scheme),
		VPCID:           derefString(lb.VpcId),
		SubnetIDs:       subnets,
		SecurityGroups:  sgs,
		TargetGroupARNs: tgARNs,
	}
}

func toGWLBData(lb *elbv2types.LoadBalancer, tgARNs []string) *domain.GWLBData {
	var subnets []string
	for _, az := range lb.AvailabilityZones {
		if az.SubnetId != nil {
			subnets = append(subnets, *az.SubnetId)
		}
	}
	return &domain.GWLBData{
		ARN:             derefString(lb.LoadBalancerArn),
		DNSName:         derefString(lb.DNSName),
		VPCID:           derefString(lb.VpcId),
		SubnetIDs:       subnets,
		TargetGroupARNs: tgARNs,
	}
}

func toCLBData(lb *elbtypes.LoadBalancerDescription) *domain.CLBData {
	var subnets []string
	for _, s := range lb.Subnets {
		subnets = append(subnets, s)
	}
	var sgs []string
	for _, sg := range lb.SecurityGroups {
		sgs = append(sgs, sg)
	}
	var instances []string
	for _, inst := range lb.Instances {
		if inst.InstanceId != nil {
			instances = append(instances, *inst.InstanceId)
		}
	}
	return &domain.CLBData{
		Name:           derefString(lb.LoadBalancerName),
		DNSName:        derefString(lb.DNSName),
		Scheme:         derefString(lb.Scheme),
		VPCID:          derefString(lb.VPCId),
		SubnetIDs:      subnets,
		SecurityGroups: sgs,
		InstanceIDs:    instances,
	}
}

func toTargetGroupData(tg *elbv2types.TargetGroup, healthDescs []elbv2types.TargetHealthDescription) *domain.TargetGroupData {
	var targets []domain.TargetData
	for _, h := range healthDescs {
		if h.Target != nil {
			status := "unknown"
			if h.TargetHealth != nil {
				status = string(h.TargetHealth.State)
			}
			targets = append(targets, domain.TargetData{
				ID:           derefString(h.Target.Id),
				Port:         int(derefInt32(h.Target.Port)),
				HealthStatus: status,
			})
		}
	}
	return &domain.TargetGroupData{
		ARN:        derefString(tg.TargetGroupArn),
		Name:       derefString(tg.TargetGroupName),
		TargetType: string(tg.TargetType),
		Protocol:   string(tg.Protocol),
		Port:       int(derefInt32(tg.Port)),
		VPCID:      derefString(tg.VpcId),
		Targets:    targets,
	}
}

func toENIData(eni *ec2types.NetworkInterface) *domain.ENIData {
	var privateIPs []string
	for _, addr := range eni.PrivateIpAddresses {
		privateIPs = append(privateIPs, derefString(addr.PrivateIpAddress))
	}

	var sgs []string
	for _, sg := range eni.Groups {
		sgs = append(sgs, derefString(sg.GroupId))
	}

	return &domain.ENIData{
		ID:             derefString(eni.NetworkInterfaceId),
		PrivateIP:      derefString(eni.PrivateIpAddress),
		PrivateIPs:     privateIPs,
		SubnetID:       derefString(eni.SubnetId),
		SecurityGroups: sgs,
	}
}

func toElastiCacheClusterData(cluster *elasticachetypes.CacheCluster) *domain.ElastiCacheClusterData {
	var sgs []string
	for _, sg := range cluster.SecurityGroups {
		if sg.SecurityGroupId != nil {
			sgs = append(sgs, *sg.SecurityGroupId)
		}
	}

	port := 0
	if cluster.ConfigurationEndpoint != nil && cluster.ConfigurationEndpoint.Port != nil {
		port = int(*cluster.ConfigurationEndpoint.Port)
	}

	var nodes []domain.ElastiCacheNodeData
	for _, node := range cluster.CacheNodes {
		nodeData := domain.ElastiCacheNodeData{
			ID: derefString(node.CacheNodeId),
		}
		if node.Endpoint != nil {
			nodeData.Endpoint = derefString(node.Endpoint.Address)
			if node.Endpoint.Port != nil {
				nodeData.Port = int(*node.Endpoint.Port)
				if port == 0 {
					port = nodeData.Port
				}
			}
			nodeData.PrivateIP = resolveEndpointToIP(nodeData.Endpoint)
		}
		nodes = append(nodes, nodeData)
	}

	return &domain.ElastiCacheClusterData{
		ID:             derefString(cluster.CacheClusterId),
		Engine:         derefString(cluster.Engine),
		EngineVersion:  derefString(cluster.EngineVersion),
		NodeType:       derefString(cluster.CacheNodeType),
		NumNodes:       int(derefInt32(cluster.NumCacheNodes)),
		Port:           port,
		Nodes:          nodes,
		SecurityGroups: sgs,
	}
}

func resolveEndpointToIP(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	ips, err := net.LookupHost(endpoint)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}
