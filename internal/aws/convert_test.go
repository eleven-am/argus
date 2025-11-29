package aws

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func TestToSecurityGroupData(t *testing.T) {
	sg := &ec2types.SecurityGroup{
		GroupId: aws.String("sg-123"),
		VpcId:   aws.String("vpc-abc"),
		IpPermissions: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("tcp"),
				FromPort:   aws.Int32(443),
				ToPort:     aws.Int32(443),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}},
			},
		},
		IpPermissionsEgress: []ec2types.IpPermission{
			{
				IpProtocol: aws.String("-1"),
				FromPort:   aws.Int32(0),
				ToPort:     aws.Int32(0),
				IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
		},
	}

	result := toSecurityGroupData(sg)

	if result.ID != "sg-123" {
		t.Errorf("expected ID sg-123, got %s", result.ID)
	}
	if result.VPCID != "vpc-abc" {
		t.Errorf("expected VPCID vpc-abc, got %s", result.VPCID)
	}
	if len(result.InboundRules) != 1 {
		t.Fatalf("expected 1 inbound rule, got %d", len(result.InboundRules))
	}
	if result.InboundRules[0].Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", result.InboundRules[0].Protocol)
	}
	if result.InboundRules[0].FromPort != 443 {
		t.Errorf("expected from port 443, got %d", result.InboundRules[0].FromPort)
	}
	if len(result.OutboundRules) != 1 {
		t.Fatalf("expected 1 outbound rule, got %d", len(result.OutboundRules))
	}
}

func TestToSecurityGroupRules_IPv6(t *testing.T) {
	perms := []ec2types.IpPermission{
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(80),
			ToPort:     aws.Int32(80),
			Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}},
		},
	}

	rules := toSecurityGroupRules(perms)

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if len(rules[0].IPv6CIDRBlocks) != 1 {
		t.Fatalf("expected 1 IPv6 CIDR block, got %d", len(rules[0].IPv6CIDRBlocks))
	}
	if rules[0].IPv6CIDRBlocks[0] != "::/0" {
		t.Errorf("expected ::/0, got %s", rules[0].IPv6CIDRBlocks[0])
	}
}

func TestToSecurityGroupRules_ReferencedSGs(t *testing.T) {
	perms := []ec2types.IpPermission{
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(443),
			ToPort:     aws.Int32(443),
			UserIdGroupPairs: []ec2types.UserIdGroupPair{
				{GroupId: aws.String("sg-referenced")},
			},
		},
	}

	rules := toSecurityGroupRules(perms)

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if len(rules[0].ReferencedSecurityGroups) != 1 {
		t.Fatalf("expected 1 referenced SG, got %d", len(rules[0].ReferencedSecurityGroups))
	}
	if rules[0].ReferencedSecurityGroups[0] != "sg-referenced" {
		t.Errorf("expected sg-referenced, got %s", rules[0].ReferencedSecurityGroups[0])
	}
}

func TestToSecurityGroupRules_PrefixLists(t *testing.T) {
	perms := []ec2types.IpPermission{
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(443),
			ToPort:     aws.Int32(443),
			PrefixListIds: []ec2types.PrefixListId{
				{PrefixListId: aws.String("pl-123")},
			},
		},
	}

	rules := toSecurityGroupRules(perms)

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if len(rules[0].PrefixListIDs) != 1 {
		t.Fatalf("expected 1 prefix list, got %d", len(rules[0].PrefixListIDs))
	}
	if rules[0].PrefixListIDs[0] != "pl-123" {
		t.Errorf("expected pl-123, got %s", rules[0].PrefixListIDs[0])
	}
}

func TestToSubnetData(t *testing.T) {
	subnet := &ec2types.Subnet{
		SubnetId:  aws.String("subnet-123"),
		VpcId:     aws.String("vpc-abc"),
		CidrBlock: aws.String("10.0.1.0/24"),
	}

	result := toSubnetData(subnet, "acl-456", "rtb-789")

	if result.ID != "subnet-123" {
		t.Errorf("expected ID subnet-123, got %s", result.ID)
	}
	if result.VPCID != "vpc-abc" {
		t.Errorf("expected VPCID vpc-abc, got %s", result.VPCID)
	}
	if result.CIDRBlock != "10.0.1.0/24" {
		t.Errorf("expected CIDR 10.0.1.0/24, got %s", result.CIDRBlock)
	}
	if result.NaclID != "acl-456" {
		t.Errorf("expected NaclID acl-456, got %s", result.NaclID)
	}
	if result.RouteTableID != "rtb-789" {
		t.Errorf("expected RouteTableID rtb-789, got %s", result.RouteTableID)
	}
}

func TestToNACLData(t *testing.T) {
	nacl := &ec2types.NetworkAcl{
		NetworkAclId: aws.String("acl-123"),
		VpcId:        aws.String("vpc-abc"),
		Entries: []ec2types.NetworkAclEntry{
			{
				RuleNumber: aws.Int32(100),
				Protocol:   aws.String("6"),
				CidrBlock:  aws.String("10.0.0.0/8"),
				RuleAction: ec2types.RuleActionAllow,
				Egress:     aws.Bool(false),
				PortRange:  &ec2types.PortRange{From: aws.Int32(443), To: aws.Int32(443)},
			},
			{
				RuleNumber: aws.Int32(100),
				Protocol:   aws.String("-1"),
				CidrBlock:  aws.String("0.0.0.0/0"),
				RuleAction: ec2types.RuleActionAllow,
				Egress:     aws.Bool(true),
			},
		},
	}

	result := toNACLData(nacl)

	if result.ID != "acl-123" {
		t.Errorf("expected ID acl-123, got %s", result.ID)
	}
	if len(result.InboundRules) != 1 {
		t.Fatalf("expected 1 inbound rule, got %d", len(result.InboundRules))
	}
	if result.InboundRules[0].Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", result.InboundRules[0].Protocol)
	}
	if result.InboundRules[0].FromPort != 443 {
		t.Errorf("expected from port 443, got %d", result.InboundRules[0].FromPort)
	}
	if len(result.OutboundRules) != 1 {
		t.Fatalf("expected 1 outbound rule, got %d", len(result.OutboundRules))
	}
}

func TestToRouteTableData(t *testing.T) {
	rt := &ec2types.RouteTable{
		RouteTableId: aws.String("rtb-123"),
		VpcId:        aws.String("vpc-abc"),
		Routes: []ec2types.Route{
			{
				DestinationCidrBlock: aws.String("0.0.0.0/0"),
				GatewayId:            aws.String("igw-456"),
			},
			{
				DestinationCidrBlock: aws.String("10.0.0.0/16"),
				GatewayId:            aws.String("local"),
			},
		},
	}

	result := toRouteTableData(rt)

	if result.ID != "rtb-123" {
		t.Errorf("expected ID rtb-123, got %s", result.ID)
	}
	if len(result.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(result.Routes))
	}
	if result.Routes[0].TargetType != "internet-gateway" {
		t.Errorf("expected target type internet-gateway, got %s", result.Routes[0].TargetType)
	}
	if result.Routes[0].TargetID != "igw-456" {
		t.Errorf("expected target ID igw-456, got %s", result.Routes[0].TargetID)
	}
	if result.Routes[1].TargetType != "local" {
		t.Errorf("expected target type local, got %s", result.Routes[1].TargetType)
	}
}

func TestDetermineRouteTarget(t *testing.T) {
	tests := []struct {
		name     string
		route    ec2types.Route
		wantType string
		wantID   string
	}{
		{
			name:     "internet gateway",
			route:    ec2types.Route{GatewayId: aws.String("igw-123")},
			wantType: "internet-gateway",
			wantID:   "igw-123",
		},
		{
			name:     "local",
			route:    ec2types.Route{GatewayId: aws.String("local")},
			wantType: "local",
			wantID:   "local",
		},
		{
			name:     "nat gateway",
			route:    ec2types.Route{NatGatewayId: aws.String("nat-123")},
			wantType: "nat-gateway",
			wantID:   "nat-123",
		},
		{
			name:     "transit gateway",
			route:    ec2types.Route{TransitGatewayId: aws.String("tgw-123")},
			wantType: "transit-gateway",
			wantID:   "tgw-123",
		},
		{
			name:     "vpc peering",
			route:    ec2types.Route{VpcPeeringConnectionId: aws.String("pcx-123")},
			wantType: "vpc-peering",
			wantID:   "pcx-123",
		},
		{
			name:     "network interface",
			route:    ec2types.Route{NetworkInterfaceId: aws.String("eni-123")},
			wantType: "network-interface",
			wantID:   "eni-123",
		},
		{
			name:     "unknown",
			route:    ec2types.Route{},
			wantType: "unknown",
			wantID:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotID := determineRouteTarget(tt.route)
			if gotType != tt.wantType {
				t.Errorf("expected type %s, got %s", tt.wantType, gotType)
			}
			if gotID != tt.wantID {
				t.Errorf("expected ID %s, got %s", tt.wantID, gotID)
			}
		})
	}
}

func TestToVPCData(t *testing.T) {
	vpc := &ec2types.Vpc{
		VpcId:     aws.String("vpc-123"),
		CidrBlock: aws.String("10.0.0.0/16"),
	}

	result := toVPCData(vpc, "rtb-main")

	if result.ID != "vpc-123" {
		t.Errorf("expected ID vpc-123, got %s", result.ID)
	}
	if result.CIDRBlock != "10.0.0.0/16" {
		t.Errorf("expected CIDR 10.0.0.0/16, got %s", result.CIDRBlock)
	}
	if result.MainRouteTableID != "rtb-main" {
		t.Errorf("expected MainRouteTableID rtb-main, got %s", result.MainRouteTableID)
	}
}

func TestToEC2InstanceData(t *testing.T) {
	inst := &ec2types.Instance{
		InstanceId:       aws.String("i-123"),
		PrivateIpAddress: aws.String("10.0.1.50"),
		SubnetId:         aws.String("subnet-456"),
		SecurityGroups: []ec2types.GroupIdentifier{
			{GroupId: aws.String("sg-111")},
			{GroupId: aws.String("sg-222")},
		},
	}

	result := toEC2InstanceData(inst)

	if result.ID != "i-123" {
		t.Errorf("expected ID i-123, got %s", result.ID)
	}
	if result.PrivateIP != "10.0.1.50" {
		t.Errorf("expected PrivateIP 10.0.1.50, got %s", result.PrivateIP)
	}
	if result.SubnetID != "subnet-456" {
		t.Errorf("expected SubnetID subnet-456, got %s", result.SubnetID)
	}
	if len(result.SecurityGroups) != 2 {
		t.Fatalf("expected 2 security groups, got %d", len(result.SecurityGroups))
	}
}

func TestToRDSInstanceData(t *testing.T) {
	db := &rdstypes.DBInstance{
		DBInstanceIdentifier: aws.String("mydb"),
		Endpoint: &rdstypes.Endpoint{
			Address: aws.String("mydb.cluster.us-east-1.rds.amazonaws.com"),
			Port:    aws.Int32(5432),
		},
		VpcSecurityGroups: []rdstypes.VpcSecurityGroupMembership{
			{VpcSecurityGroupId: aws.String("sg-333")},
		},
		DBSubnetGroup: &rdstypes.DBSubnetGroup{
			Subnets: []rdstypes.Subnet{
				{SubnetIdentifier: aws.String("subnet-a")},
				{SubnetIdentifier: aws.String("subnet-b")},
			},
		},
	}

	result := toRDSInstanceData(db, "10.0.1.50")

	if result.ID != "mydb" {
		t.Errorf("expected ID mydb, got %s", result.ID)
	}
	if result.Port != 5432 {
		t.Errorf("expected Port 5432, got %d", result.Port)
	}
	if result.PrivateIP != "10.0.1.50" {
		t.Errorf("expected PrivateIP 10.0.1.50, got %s", result.PrivateIP)
	}
	if len(result.SecurityGroups) != 1 {
		t.Fatalf("expected 1 security group, got %d", len(result.SecurityGroups))
	}
	if len(result.SubnetIDs) != 2 {
		t.Fatalf("expected 2 subnets, got %d", len(result.SubnetIDs))
	}
}

func TestToInternetGatewayData(t *testing.T) {
	igw := &ec2types.InternetGateway{
		InternetGatewayId: aws.String("igw-123"),
		Attachments: []ec2types.InternetGatewayAttachment{
			{VpcId: aws.String("vpc-abc")},
		},
	}

	result := toInternetGatewayData(igw)

	if result.ID != "igw-123" {
		t.Errorf("expected ID igw-123, got %s", result.ID)
	}
	if result.VPCID != "vpc-abc" {
		t.Errorf("expected VPCID vpc-abc, got %s", result.VPCID)
	}
}

func TestToNATGatewayData(t *testing.T) {
	nat := &ec2types.NatGateway{
		NatGatewayId: aws.String("nat-123"),
		SubnetId:     aws.String("subnet-456"),
		NatGatewayAddresses: []ec2types.NatGatewayAddress{
			{PublicIp: aws.String("54.1.2.3")},
		},
	}

	result := toNATGatewayData(nat)

	if result.ID != "nat-123" {
		t.Errorf("expected ID nat-123, got %s", result.ID)
	}
	if result.SubnetID != "subnet-456" {
		t.Errorf("expected SubnetID subnet-456, got %s", result.SubnetID)
	}
	if result.PublicIP != "54.1.2.3" {
		t.Errorf("expected PublicIP 54.1.2.3, got %s", result.PublicIP)
	}
}

func TestToVPCEndpointData(t *testing.T) {
	ep := &ec2types.VpcEndpoint{
		VpcEndpointId:   aws.String("vpce-123"),
		VpcId:           aws.String("vpc-abc"),
		ServiceName:     aws.String("com.amazonaws.us-east-1.s3"),
		VpcEndpointType: ec2types.VpcEndpointTypeGateway,
	}

	result := toVPCEndpointData(ep)

	if result.ID != "vpce-123" {
		t.Errorf("expected ID vpce-123, got %s", result.ID)
	}
	if result.ServiceName != "com.amazonaws.us-east-1.s3" {
		t.Errorf("expected ServiceName com.amazonaws.us-east-1.s3, got %s", result.ServiceName)
	}
	if result.Type != "Gateway" {
		t.Errorf("expected Type Gateway, got %s", result.Type)
	}
}

func TestToVPCPeeringData(t *testing.T) {
	pcx := &ec2types.VpcPeeringConnection{
		VpcPeeringConnectionId: aws.String("pcx-123"),
		RequesterVpcInfo:       &ec2types.VpcPeeringConnectionVpcInfo{VpcId: aws.String("vpc-requester")},
		AccepterVpcInfo: &ec2types.VpcPeeringConnectionVpcInfo{
			VpcId:   aws.String("vpc-accepter"),
			OwnerId: aws.String("111122223333"),
		},
	}

	result := toVPCPeeringData(pcx)

	if result.ID != "pcx-123" {
		t.Errorf("expected ID pcx-123, got %s", result.ID)
	}
	if result.RequesterVPC != "vpc-requester" {
		t.Errorf("expected RequesterVPC vpc-requester, got %s", result.RequesterVPC)
	}
	if result.AccepterVPC != "vpc-accepter" {
		t.Errorf("expected AccepterVPC vpc-accepter, got %s", result.AccepterVPC)
	}
	if result.AccepterOwner != "111122223333" {
		t.Errorf("expected AccepterOwner 111122223333, got %s", result.AccepterOwner)
	}
}

func TestPrefixLength(t *testing.T) {
	tests := []struct {
		cidr string
		want int
	}{
		{"10.0.0.0/8", 8},
		{"192.168.1.0/24", 24},
		{"0.0.0.0/0", 0},
		{"::/0", 0},
		{"invalid", 0},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			got := prefixLength(tt.cidr)
			if got != tt.want {
				t.Errorf("prefixLength(%s) = %d, want %d", tt.cidr, got, tt.want)
			}
		})
	}
}

func TestProtocolNumberToString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"-1", "-1"},
		{"6", "tcp"},
		{"17", "udp"},
		{"1", "icmp"},
		{"47", "47"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := protocolNumberToString(tt.input)
			if got != tt.want {
				t.Errorf("protocolNumberToString(%s) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestDerefString(t *testing.T) {
	s := "hello"
	if derefString(&s) != "hello" {
		t.Error("expected hello")
	}
	if derefString(nil) != "" {
		t.Error("expected empty string for nil")
	}
}

func TestDerefInt32(t *testing.T) {
	var i int32 = 42
	if derefInt32(&i) != 42 {
		t.Error("expected 42")
	}
	if derefInt32(nil) != 0 {
		t.Error("expected 0 for nil")
	}
}
