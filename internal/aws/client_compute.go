package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/eleven-am/argus/internal/domain"
)

func (c *Client) GetEC2Instance(ctx context.Context, instanceID string) (*domain.EC2InstanceData, error) {
	out, err := c.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe instance %s: %w", instanceID, err)
	}
	if len(out.Reservations) == 0 || len(out.Reservations[0].Instances) == 0 {
		return nil, fmt.Errorf("instance %s not found", instanceID)
	}
	return toEC2InstanceData(&out.Reservations[0].Instances[0]), nil
}

func (c *Client) GetRDSInstance(ctx context.Context, dbInstanceID string) (*domain.RDSInstanceData, error) {
	out, err := c.rdsClient.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(dbInstanceID),
	})
	if err != nil {
		return nil, fmt.Errorf("describe rds instance %s: %w", dbInstanceID, err)
	}
	if len(out.DBInstances) == 0 {
		return nil, fmt.Errorf("rds instance %s not found", dbInstanceID)
	}

	db := &out.DBInstances[0]
	privateIP := ""

	if db.DBInstanceArn != nil {
		eniOut, err := c.ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
			Filters: []ec2types.Filter{
				{Name: aws.String("requester-id"), Values: []string{"amazon-rds"}},
				{Name: aws.String("description"), Values: []string{fmt.Sprintf("*%s*", dbInstanceID)}},
			},
		})
		if err == nil && len(eniOut.NetworkInterfaces) > 0 {
			privateIP = derefString(eniOut.NetworkInterfaces[0].PrivateIpAddress)
		}
	}

	return toRDSInstanceData(db, privateIP), nil
}

func (c *Client) GetLambdaFunction(ctx context.Context, functionName string) (*domain.LambdaFunctionData, error) {
	out, err := c.lambdaClient.GetFunction(ctx, &lambda.GetFunctionInput{
		FunctionName: aws.String(functionName),
	})
	if err != nil {
		return nil, fmt.Errorf("get lambda function %s: %w", functionName, err)
	}

	data := toLambdaFunctionData(out)

	if len(data.SubnetIDs) > 0 {
		subnetOut, err := c.ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			SubnetIds: data.SubnetIDs,
		})
		if err == nil {
			for _, subnet := range subnetOut.Subnets {
				if subnet.CidrBlock != nil {
					data.SubnetCIDRs = append(data.SubnetCIDRs, *subnet.CidrBlock)
				}
			}
		}
	}

	return data, nil
}

func (c *Client) GetVirtualPrivateGateway(ctx context.Context, vgwID string) (*domain.VirtualPrivateGatewayData, error) {
	out, err := c.ec2Client.DescribeVpnGateways(ctx, &ec2.DescribeVpnGatewaysInput{
		VpnGatewayIds: []string{vgwID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe vpn gateway %s: %w", vgwID, err)
	}
	if len(out.VpnGateways) == 0 {
		return nil, fmt.Errorf("vpn gateway %s not found", vgwID)
	}
	vgw := &out.VpnGateways[0]
	var vpcID string
	for _, att := range vgw.VpcAttachments {
		if att.State == ec2types.AttachmentStatusAttached {
			vpcID = derefString(att.VpcId)
			break
		}
	}
	return &domain.VirtualPrivateGatewayData{
		ID:    derefString(vgw.VpnGatewayId),
		VPCID: vpcID,
	}, nil
}

func (c *Client) GetVPNConnection(ctx context.Context, vpnID string) (*domain.VPNConnectionData, error) {
	out, err := c.ec2Client.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{
		VpnConnectionIds: []string{vpnID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe vpn connection %s: %w", vpnID, err)
	}
	if len(out.VpnConnections) == 0 {
		return nil, fmt.Errorf("vpn connection %s not found", vpnID)
	}
	vpn := &out.VpnConnections[0]
	hasUpTunnel := false
	for _, tel := range vpn.VgwTelemetry {
		if tel.Status == ec2types.TelemetryStatusUp {
			hasUpTunnel = true
			break
		}
	}
	return &domain.VPNConnectionData{
		ID:          derefString(vpn.VpnConnectionId),
		VGWID:       derefString(vpn.VpnGatewayId),
		State:       string(vpn.State),
		HasUpTunnel: hasUpTunnel,
	}, nil
}

func (c *Client) GetVPNConnectionsByVGW(ctx context.Context, vgwID string) ([]*domain.VPNConnectionData, error) {
	out, err := c.ec2Client.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("vpn-gateway-id"),
				Values: []string{vgwID},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe vpn connections for vgw %s: %w", vgwID, err)
	}

	var result []*domain.VPNConnectionData
	for _, vpn := range out.VpnConnections {
		hasUpTunnel := false
		for _, tel := range vpn.VgwTelemetry {
			if tel.Status == ec2types.TelemetryStatusUp {
				hasUpTunnel = true
				break
			}
		}
		result = append(result, &domain.VPNConnectionData{
			ID:          derefString(vpn.VpnConnectionId),
			VGWID:       derefString(vpn.VpnGatewayId),
			State:       string(vpn.State),
			HasUpTunnel: hasUpTunnel,
		})
	}
	return result, nil
}

func (c *Client) GetDirectConnectGateway(ctx context.Context, dxgwID string) (*domain.DirectConnectGatewayData, error) {
	return &domain.DirectConnectGatewayData{
		ID:      dxgwID,
		OwnerID: c.accountID,
	}, nil
}

func (c *Client) GetNetworkInterface(ctx context.Context, eniID string) (*domain.ENIData, error) {
	out, err := c.ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []string{eniID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe network interface %s: %w", eniID, err)
	}
	if len(out.NetworkInterfaces) == 0 {
		return nil, fmt.Errorf("network interface %s not found", eniID)
	}

	return toENIData(&out.NetworkInterfaces[0]), nil
}

func (c *Client) GetENIsBySecurityGroup(ctx context.Context, sgID string) ([]domain.ENIData, error) {
	input := &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("group-id"), Values: []string{sgID}},
		},
	}
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(c.ec2Client, input)
	networkInterfaces, err := CollectPages(
		ctx,
		paginator.HasMorePages,
		func(ctx context.Context) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return paginator.NextPage(ctx)
		},
		func(out *ec2.DescribeNetworkInterfacesOutput) []ec2types.NetworkInterface {
			return out.NetworkInterfaces
		},
	)
	if err != nil {
		return nil, fmt.Errorf("describe network interfaces for sg %s: %w", sgID, err)
	}

	var enis []domain.ENIData
	for _, eni := range networkInterfaces {
		enis = append(enis, *toENIData(&eni))
	}
	return enis, nil
}

func (c *Client) GetNetworkInterfaceByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.ENIData, error) {
	out, err := c.ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("private-ip-address"), Values: []string{ip}},
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe network interfaces for ip %s: %w", ip, err)
	}
	if len(out.NetworkInterfaces) == 0 {
		return nil, nil
	}
	return toENIData(&out.NetworkInterfaces[0]), nil
}

func (c *Client) GetEC2InstanceByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.EC2InstanceData, error) {
	out, err := c.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("private-ip-address"), Values: []string{ip}},
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe instances for ip %s: %w", ip, err)
	}
	for _, res := range out.Reservations {
		for _, inst := range res.Instances {
			return toEC2InstanceData(&inst), nil
		}
	}
	return nil, nil
}

func (c *Client) GetRDSInstanceByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.RDSInstanceData, error) {
	paginator := rds.NewDescribeDBInstancesPaginator(c.rdsClient, &rds.DescribeDBInstancesInput{})
	dbInstances, err := CollectPages(
		ctx,
		paginator.HasMorePages,
		func(ctx context.Context) (*rds.DescribeDBInstancesOutput, error) {
			return paginator.NextPage(ctx)
		},
		func(out *rds.DescribeDBInstancesOutput) []rdstypes.DBInstance {
			return out.DBInstances
		},
	)
	if err != nil {
		return nil, fmt.Errorf("describe rds instances: %w", err)
	}
	for _, db := range dbInstances {
		data := toRDSInstanceData(&db, "")
		if data != nil && data.PrivateIP == ip {
			return data, nil
		}
	}
	return nil, nil
}

func (c *Client) GetLambdaFunctionByENIIP(ctx context.Context, ip, vpcID string) (*domain.LambdaFunctionData, error) {
	out, err := c.ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("private-ip-address"), Values: []string{ip}},
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			{Name: aws.String("interface-type"), Values: []string{"lambda"}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe network interfaces for lambda ip %s: %w", ip, err)
	}
	if len(out.NetworkInterfaces) == 0 {
		return nil, nil
	}

	eni := out.NetworkInterfaces[0]
	if eni.Attachment != nil && eni.Attachment.InstanceOwnerId != nil && *eni.Attachment.InstanceOwnerId == "amazon-aws" {
		// Some lambda ENIs have owner amazon-aws
	}

	// Lambda ENIs do not expose function name directly; return placeholder data with ENI IP.
	name := derefString(eni.Description)
	// Try to extract function name from description pattern: "...(<function-name>)"
	if idx := strings.LastIndex(name, "("); idx != -1 && strings.HasSuffix(name, ")") && idx+1 < len(name)-1 {
		name = name[idx+1 : len(name)-1]
	}
	return &domain.LambdaFunctionData{
		Name:           name,
		VPCID:          derefString(eni.VpcId),
		SubnetIDs:      []string{derefString(eni.SubnetId)},
		SecurityGroups: extractENIGroupIDs(eni.Groups),
		ENIIPs:         []string{ip},
	}, nil
}

func extractENIGroupIDs(groups []ec2types.GroupIdentifier) []string {
	var ids []string
	for _, g := range groups {
		ids = append(ids, derefString(g.GroupId))
	}
	return ids
}
