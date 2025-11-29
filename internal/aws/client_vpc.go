package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/eleven-am/argus/internal/domain"
)

func (c *Client) GetSecurityGroup(ctx context.Context, sgID string) (*domain.SecurityGroupData, error) {
	key := c.cacheKey("sg", sgID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.SecurityGroupData), nil
	}
	out, err := c.ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{sgID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe security group %s: %w", sgID, err)
	}
	if len(out.SecurityGroups) == 0 {
		return nil, fmt.Errorf("security group %s not found", sgID)
	}
	data := toSecurityGroupData(&out.SecurityGroups[0])
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetSubnet(ctx context.Context, subnetID string) (*domain.SubnetData, error) {
	key := c.cacheKey("subnet", subnetID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.SubnetData), nil
	}
	subnetOut, err := c.ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: []string{subnetID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe subnet %s: %w", subnetID, err)
	}
	if len(subnetOut.Subnets) == 0 {
		return nil, fmt.Errorf("subnet %s not found", subnetID)
	}
	subnet := &subnetOut.Subnets[0]

	naclID, err := c.findNACLForSubnet(ctx, subnetID)
	if err != nil {
		return nil, err
	}

	rtID, err := c.findRouteTableForSubnet(ctx, subnetID, derefString(subnet.VpcId))
	if err != nil {
		return nil, err
	}

	data := toSubnetData(subnet, naclID, rtID)
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) findNACLForSubnet(ctx context.Context, subnetID string) (string, error) {
	out, err := c.ec2Client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("association.subnet-id"), Values: []string{subnetID}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("describe network acls for subnet %s: %w", subnetID, err)
	}
	if len(out.NetworkAcls) == 0 {
		return "", nil
	}
	return derefString(out.NetworkAcls[0].NetworkAclId), nil
}

func (c *Client) findRouteTableForSubnet(ctx context.Context, subnetID, vpcID string) (string, error) {
	out, err := c.ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("association.subnet-id"), Values: []string{subnetID}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("describe route tables for subnet %s: %w", subnetID, err)
	}
	if len(out.RouteTables) > 0 {
		return derefString(out.RouteTables[0].RouteTableId), nil
	}

	mainOut, err := c.ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			{Name: aws.String("association.main"), Values: []string{"true"}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("describe main route table for vpc %s: %w", vpcID, err)
	}
	if len(mainOut.RouteTables) > 0 {
		return derefString(mainOut.RouteTables[0].RouteTableId), nil
	}
	return "", nil
}

func (c *Client) GetNACL(ctx context.Context, naclID string) (*domain.NACLData, error) {
	key := c.cacheKey("nacl", naclID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.NACLData), nil
	}
	out, err := c.ec2Client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{
		NetworkAclIds: []string{naclID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe network acl %s: %w", naclID, err)
	}
	if len(out.NetworkAcls) == 0 {
		return nil, fmt.Errorf("network acl %s not found", naclID)
	}
	data := toNACLData(&out.NetworkAcls[0])
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetRouteTable(ctx context.Context, rtID string) (*domain.RouteTableData, error) {
	key := c.cacheKey("rt", rtID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.RouteTableData), nil
	}
	out, err := c.ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		RouteTableIds: []string{rtID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe route table %s: %w", rtID, err)
	}
	if len(out.RouteTables) == 0 {
		return nil, fmt.Errorf("route table %s not found", rtID)
	}
	data := toRouteTableData(&out.RouteTables[0])
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetVPC(ctx context.Context, vpcID string) (*domain.VPCData, error) {
	key := c.cacheKey("vpc", vpcID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.VPCData), nil
	}
	out, err := c.ec2Client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		VpcIds: []string{vpcID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe vpc %s: %w", vpcID, err)
	}
	if len(out.Vpcs) == 0 {
		return nil, fmt.Errorf("vpc %s not found", vpcID)
	}

	mainRtID, _ := c.findMainRouteTable(ctx, vpcID)
	data := toVPCData(&out.Vpcs[0], mainRtID)
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) findMainRouteTable(ctx context.Context, vpcID string) (string, error) {
	out, err := c.ec2Client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			{Name: aws.String("association.main"), Values: []string{"true"}},
		},
	})
	if err != nil {
		return "", err
	}
	if len(out.RouteTables) > 0 {
		return derefString(out.RouteTables[0].RouteTableId), nil
	}
	return "", nil
}

func (c *Client) GetInternetGateway(ctx context.Context, igwID string) (*domain.InternetGatewayData, error) {
	key := c.cacheKey("igw", igwID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.InternetGatewayData), nil
	}
	out, err := c.ec2Client.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
		InternetGatewayIds: []string{igwID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe internet gateway %s: %w", igwID, err)
	}
	if len(out.InternetGateways) == 0 {
		return nil, fmt.Errorf("internet gateway %s not found", igwID)
	}
	data := toInternetGatewayData(&out.InternetGateways[0])
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetEgressOnlyInternetGateway(ctx context.Context, eigwID string) (*domain.EgressOnlyInternetGatewayData, error) {
	key := c.cacheKey("eigw", eigwID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.EgressOnlyInternetGatewayData), nil
	}
	out, err := c.ec2Client.DescribeEgressOnlyInternetGateways(ctx, &ec2.DescribeEgressOnlyInternetGatewaysInput{
		EgressOnlyInternetGatewayIds: []string{eigwID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe egress-only internet gateway %s: %w", eigwID, err)
	}
	if len(out.EgressOnlyInternetGateways) == 0 {
		return nil, fmt.Errorf("egress-only internet gateway %s not found", eigwID)
	}
	data := toEgressOnlyInternetGatewayData(&out.EgressOnlyInternetGateways[0])
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetNATGateway(ctx context.Context, natID string) (*domain.NATGatewayData, error) {
	key := c.cacheKey("nat", natID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.NATGatewayData), nil
	}
	out, err := c.ec2Client.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
		NatGatewayIds: []string{natID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe nat gateway %s: %w", natID, err)
	}
	if len(out.NatGateways) == 0 {
		return nil, fmt.Errorf("nat gateway %s not found", natID)
	}
	data := toNATGatewayData(&out.NatGateways[0])
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetVPCEndpoint(ctx context.Context, endpointID string) (*domain.VPCEndpointData, error) {
	key := c.cacheKey("vpce", endpointID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.VPCEndpointData), nil
	}
	out, err := c.ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
		VpcEndpointIds: []string{endpointID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe vpc endpoint %s: %w", endpointID, err)
	}
	if len(out.VpcEndpoints) == 0 {
		return nil, fmt.Errorf("vpc endpoint %s not found", endpointID)
	}
	data := toVPCEndpointData(&out.VpcEndpoints[0])
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetVPCPeering(ctx context.Context, peeringID string) (*domain.VPCPeeringData, error) {
	key := c.cacheKey("pcx", peeringID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.VPCPeeringData), nil
	}
	out, err := c.ec2Client.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{
		VpcPeeringConnectionIds: []string{peeringID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe vpc peering %s: %w", peeringID, err)
	}
	if len(out.VpcPeeringConnections) == 0 {
		return nil, fmt.Errorf("vpc peering %s not found", peeringID)
	}
	data := toVPCPeeringData(&out.VpcPeeringConnections[0])
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetManagedPrefixList(ctx context.Context, prefixListID string) (*domain.ManagedPrefixListData, error) {
	key := c.cacheKey("pl", prefixListID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.ManagedPrefixListData), nil
	}
	out, err := c.ec2Client.DescribeManagedPrefixLists(ctx, &ec2.DescribeManagedPrefixListsInput{
		PrefixListIds: []string{prefixListID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe managed prefix list %s: %w", prefixListID, err)
	}
	if len(out.PrefixLists) == 0 {
		return nil, fmt.Errorf("managed prefix list %s not found", prefixListID)
	}

	entriesOut, err := c.ec2Client.GetManagedPrefixListEntries(ctx, &ec2.GetManagedPrefixListEntriesInput{
		PrefixListId: aws.String(prefixListID),
	})
	if err != nil {
		return nil, fmt.Errorf("get managed prefix list entries %s: %w", prefixListID, err)
	}

	pl := &out.PrefixLists[0]
	result := &domain.ManagedPrefixListData{
		ID:   derefString(pl.PrefixListId),
		Name: derefString(pl.PrefixListName),
	}

	for _, entry := range entriesOut.Entries {
		result.Entries = append(result.Entries, domain.PrefixListEntry{
			CIDR:        derefString(entry.Cidr),
			Description: derefString(entry.Description),
		})
	}

	c.cache.set(key, result)
	return result, nil
}
