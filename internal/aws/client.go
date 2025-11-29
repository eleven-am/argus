package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/directconnect"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	nfwtypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"golang.org/x/sync/errgroup"

	"github.com/eleven-am/argus/internal/domain"
)

type Client struct {
	ec2Client             *ec2.Client
	rdsClient             *rds.Client
	lambdaClient          *lambda.Client
	elbClient             *elb.Client
	elbv2Client           *elbv2.Client
	apigwClient           *apigateway.Client
	apigwv2Client         *apigatewayv2.Client
	elasticacheClient     *elasticache.Client
	directconnectClient   *directconnect.Client
	networkFirewallClient *networkfirewall.Client
	accountID             string
	region                string
	cache                 *ttlCache
}

func newRetryer() aws.Retryer {
	return retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = 5
		o.MaxBackoff = 30 * time.Second
		o.Backoff = retry.NewExponentialJitterBackoff(o.MaxBackoff)
		o.RateLimiter = ratelimit.None
	})
}

func NewClient(cfg aws.Config, accountID, region string) *Client {
	retryer := newRetryer()
	return &Client{
		ec2Client:             ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Retryer = retryer }),
		rdsClient:             rds.NewFromConfig(cfg, func(o *rds.Options) { o.Retryer = retryer }),
		lambdaClient:          lambda.NewFromConfig(cfg, func(o *lambda.Options) { o.Retryer = retryer }),
		elbClient:             elb.NewFromConfig(cfg, func(o *elb.Options) { o.Retryer = retryer }),
		elbv2Client:           elbv2.NewFromConfig(cfg, func(o *elbv2.Options) { o.Retryer = retryer }),
		apigwClient:           apigateway.NewFromConfig(cfg, func(o *apigateway.Options) { o.Retryer = retryer }),
		apigwv2Client:         apigatewayv2.NewFromConfig(cfg, func(o *apigatewayv2.Options) { o.Retryer = retryer }),
		elasticacheClient:     elasticache.NewFromConfig(cfg, func(o *elasticache.Options) { o.Retryer = retryer }),
		directconnectClient:   directconnect.NewFromConfig(cfg, func(o *directconnect.Options) { o.Retryer = retryer }),
		networkFirewallClient: networkfirewall.NewFromConfig(cfg, func(o *networkfirewall.Options) { o.Retryer = retryer }),
		accountID:             accountID,
		region:                region,
		cache:                 newTTLCache(5*time.Minute, 2000),
	}
}

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

func (c *Client) GetTransitGateway(ctx context.Context, tgwID string) (*domain.TransitGatewayData, error) {
	key := c.cacheKey("tgw", tgwID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.TransitGatewayData), nil
	}
	out, err := c.ec2Client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{
		TransitGatewayIds: []string{tgwID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe transit gateway %s: %w", tgwID, err)
	}
	if len(out.TransitGateways) == 0 {
		return nil, fmt.Errorf("transit gateway %s not found", tgwID)
	}

	rts, err := c.fetchTGWRouteTables(ctx, tgwID)
	if err != nil {
		return nil, err
	}

	data := toTransitGatewayData(&out.TransitGateways[0], rts)
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) fetchTGWRouteTables(ctx context.Context, tgwID string) ([]domain.TGWRouteTableData, error) {
	input := &ec2.DescribeTransitGatewayRouteTablesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("transit-gateway-id"), Values: []string{tgwID}},
		},
	}
	paginator := ec2.NewDescribeTransitGatewayRouteTablesPaginator(c.ec2Client, input)
	routeTables, err := CollectPages(
		ctx,
		paginator.HasMorePages,
		func(ctx context.Context) (*ec2.DescribeTransitGatewayRouteTablesOutput, error) {
			return paginator.NextPage(ctx)
		},
		func(out *ec2.DescribeTransitGatewayRouteTablesOutput) []ec2types.TransitGatewayRouteTable {
			return out.TransitGatewayRouteTables
		},
	)
	if err != nil {
		return nil, fmt.Errorf("describe tgw route tables for %s: %w", tgwID, err)
	}

	results := make([]domain.TGWRouteTableData, len(routeTables))
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for i, rt := range routeTables {
		i, rt := i, rt
		g.Go(func() error {
			rtID := derefString(rt.TransitGatewayRouteTableId)

			var routes []domain.TGWRoute
			var associations []domain.TGWRouteTableAssociation
			var propagations []domain.TGWRouteTablePropagation

			innerG, innerCtx := errgroup.WithContext(gCtx)

			innerG.Go(func() error {
				var err error
				routes, err = c.searchTGWRoutes(innerCtx, rtID)
				return err
			})
			innerG.Go(func() error {
				var err error
				associations, err = c.fetchTGWRouteTableAssociations(innerCtx, rtID)
				return err
			})
			innerG.Go(func() error {
				var err error
				propagations, err = c.fetchTGWRouteTablePropagations(innerCtx, rtID)
				return err
			})

			if err := innerG.Wait(); err != nil {
				return err
			}

			results[i] = domain.TGWRouteTableData{
				ID:           rtID,
				Routes:       routes,
				Associations: associations,
				Propagations: propagations,
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
}

func (c *Client) fetchTGWRouteTableAssociations(ctx context.Context, rtID string) ([]domain.TGWRouteTableAssociation, error) {
	out, err := c.ec2Client.GetTransitGatewayRouteTableAssociations(ctx, &ec2.GetTransitGatewayRouteTableAssociationsInput{
		TransitGatewayRouteTableId: aws.String(rtID),
	})
	if err != nil {
		return nil, fmt.Errorf("get tgw route table associations for %s: %w", rtID, err)
	}

	var associations []domain.TGWRouteTableAssociation
	for _, a := range out.Associations {
		associations = append(associations, domain.TGWRouteTableAssociation{
			AttachmentID: derefString(a.TransitGatewayAttachmentId),
			ResourceType: string(a.ResourceType),
			State:        string(a.State),
		})
	}
	return associations, nil
}

func (c *Client) fetchTGWRouteTablePropagations(ctx context.Context, rtID string) ([]domain.TGWRouteTablePropagation, error) {
	out, err := c.ec2Client.GetTransitGatewayRouteTablePropagations(ctx, &ec2.GetTransitGatewayRouteTablePropagationsInput{
		TransitGatewayRouteTableId: aws.String(rtID),
	})
	if err != nil {
		return nil, fmt.Errorf("get tgw route table propagations for %s: %w", rtID, err)
	}

	var propagations []domain.TGWRouteTablePropagation
	for _, p := range out.TransitGatewayRouteTablePropagations {
		propagations = append(propagations, domain.TGWRouteTablePropagation{
			AttachmentID: derefString(p.TransitGatewayAttachmentId),
			ResourceType: string(p.ResourceType),
			State:        string(p.State),
		})
	}
	return propagations, nil
}

func (c *Client) searchTGWRoutes(ctx context.Context, rtID string) ([]domain.TGWRoute, error) {
	searchFilters := []ec2types.Filter{
		{Name: aws.String("type"), Values: []string{"static", "propagated"}},
	}

	out, err := c.ec2Client.SearchTransitGatewayRoutes(ctx, &ec2.SearchTransitGatewayRoutesInput{
		TransitGatewayRouteTableId: aws.String(rtID),
		Filters:                    searchFilters,
	})
	if err != nil {
		return nil, fmt.Errorf("search tgw routes for %s: %w", rtID, err)
	}

	var routes []domain.TGWRoute
	attachmentIDs := make(map[string]struct{})
	for _, r := range out.Routes {
		for _, att := range r.TransitGatewayAttachments {
			if att.TransitGatewayAttachmentId != nil {
				attachmentIDs[*att.TransitGatewayAttachmentId] = struct{}{}
			}
		}
	}

	attDetailsMap := make(map[string]ec2types.TransitGatewayAttachment)
	if len(attachmentIDs) > 0 {
		var ids []string
		for id := range attachmentIDs {
			ids = append(ids, id)
		}
		details, err := c.ec2Client.DescribeTransitGatewayAttachments(ctx, &ec2.DescribeTransitGatewayAttachmentsInput{
			TransitGatewayAttachmentIds: ids,
		})
		if err == nil {
			for _, att := range details.TransitGatewayAttachments {
				if att.TransitGatewayAttachmentId != nil {
					attDetailsMap[*att.TransitGatewayAttachmentId] = att
				}
			}
		}
	}

	for _, r := range out.Routes {
		route := domain.TGWRoute{
			DestinationCIDR: derefString(r.DestinationCidrBlock),
			PrefixLength:    prefixLength(derefString(r.DestinationCidrBlock)),
			State:           string(r.State),
		}

		for _, att := range r.TransitGatewayAttachments {
			attState := ""
			ownerID := ""
			if att.TransitGatewayAttachmentId != nil {
				if det, ok := attDetailsMap[*att.TransitGatewayAttachmentId]; ok {
					attState = string(det.State)
					ownerID = derefString(det.ResourceOwnerId)
				}
			}

			route.Attachments = append(route.Attachments, domain.TGWRouteAttachment{
				ID:         derefString(att.TransitGatewayAttachmentId),
				Type:       string(att.ResourceType),
				ResourceID: derefString(att.ResourceId),
				OwnerID:    ownerID,
				State:      attState,
			})
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func (c *Client) GetTransitGatewayAttachment(ctx context.Context, vpcID, tgwID string) (*domain.TGWAttachmentData, error) {
	key := c.cacheKey("tgw-attach-vpc", vpcID+":"+tgwID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.TGWAttachmentData), nil
	}
	out, err := c.ec2Client.DescribeTransitGatewayVpcAttachments(ctx, &ec2.DescribeTransitGatewayVpcAttachmentsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
			{Name: aws.String("transit-gateway-id"), Values: []string{tgwID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe tgw attachment for vpc %s tgw %s: %w", vpcID, tgwID, err)
	}
	if len(out.TransitGatewayVpcAttachments) == 0 {
		return nil, fmt.Errorf("tgw attachment not found for vpc %s tgw %s", vpcID, tgwID)
	}

	att := &out.TransitGatewayVpcAttachments[0]
	attachmentID := derefString(att.TransitGatewayAttachmentId)

	tgwOwnerID := ""
	tgwOut, err := c.ec2Client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{
		TransitGatewayIds: []string{tgwID},
	})
	if err == nil && len(tgwOut.TransitGateways) > 0 {
		tgwOwnerID = derefString(tgwOut.TransitGateways[0].OwnerId)
	}

	state := string(att.State)

	propagatedRTIDs, err := c.getPropagatedRouteTableIDs(ctx, tgwID, attachmentID)
	if err != nil {
		propagatedRTIDs = nil
	}

	data := toTGWAttachmentData(att, tgwOwnerID, state, propagatedRTIDs)
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetTransitGatewayAttachmentByID(ctx context.Context, attachmentID string) (*domain.TGWAttachmentData, error) {
	key := c.cacheKey("tgw-attach", attachmentID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.TGWAttachmentData), nil
	}
	out, err := c.ec2Client.DescribeTransitGatewayVpcAttachments(ctx, &ec2.DescribeTransitGatewayVpcAttachmentsInput{
		TransitGatewayAttachmentIds: []string{attachmentID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe tgw attachment %s: %w", attachmentID, err)
	}
	if len(out.TransitGatewayVpcAttachments) == 0 {
		return nil, fmt.Errorf("tgw attachment %s not found", attachmentID)
	}

	att := &out.TransitGatewayVpcAttachments[0]
	tgwID := derefString(att.TransitGatewayId)

	tgwOwnerID := ""
	if tgwID != "" {
		tgwOut, err := c.ec2Client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{
			TransitGatewayIds: []string{tgwID},
		})
		if err == nil && len(tgwOut.TransitGateways) > 0 {
			tgwOwnerID = derefString(tgwOut.TransitGateways[0].OwnerId)
		}
	}

	state := string(att.State)

	propagatedRTIDs, err := c.getPropagatedRouteTableIDs(ctx, tgwID, attachmentID)
	if err != nil {
		propagatedRTIDs = nil
	}

	data := toTGWAttachmentData(att, tgwOwnerID, state, propagatedRTIDs)
	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetRouteTablesForAttachment(ctx context.Context, tgwID, attachmentID string) (associated []string, propagated []string, err error) {
	input := &ec2.DescribeTransitGatewayRouteTablesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("transit-gateway-id"), Values: []string{tgwID}},
		},
	}
	paginator := ec2.NewDescribeTransitGatewayRouteTablesPaginator(c.ec2Client, input)
	routeTables, err := CollectPages(
		ctx,
		paginator.HasMorePages,
		func(ctx context.Context) (*ec2.DescribeTransitGatewayRouteTablesOutput, error) {
			return paginator.NextPage(ctx)
		},
		func(out *ec2.DescribeTransitGatewayRouteTablesOutput) []ec2types.TransitGatewayRouteTable {
			return out.TransitGatewayRouteTables
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("describe tgw route tables for %s: %w", tgwID, err)
	}

	type rtResult struct {
		rtID       string
		associated bool
		propagated bool
	}

	results := make([]rtResult, len(routeTables))
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(10)

	for i, rt := range routeTables {
		i, rt := i, rt
		g.Go(func() error {
			rtID := derefString(rt.TransitGatewayRouteTableId)
			results[i].rtID = rtID

			innerG, innerCtx := errgroup.WithContext(gCtx)

			innerG.Go(func() error {
				assocOut, err := c.ec2Client.GetTransitGatewayRouteTableAssociations(innerCtx, &ec2.GetTransitGatewayRouteTableAssociationsInput{
					TransitGatewayRouteTableId: aws.String(rtID),
				})
				if err == nil {
					for _, a := range assocOut.Associations {
						if derefString(a.TransitGatewayAttachmentId) == attachmentID && a.State == ec2types.TransitGatewayAssociationStateAssociated {
							results[i].associated = true
							break
						}
					}
				}
				return nil
			})

			innerG.Go(func() error {
				propOut, err := c.ec2Client.GetTransitGatewayRouteTablePropagations(innerCtx, &ec2.GetTransitGatewayRouteTablePropagationsInput{
					TransitGatewayRouteTableId: aws.String(rtID),
				})
				if err == nil {
					for _, p := range propOut.TransitGatewayRouteTablePropagations {
						if derefString(p.TransitGatewayAttachmentId) == attachmentID && p.State == ec2types.TransitGatewayPropagationStateEnabled {
							results[i].propagated = true
							break
						}
					}
				}
				return nil
			})

			innerG.Wait()
			return nil
		})
	}

	g.Wait()

	for _, r := range results {
		if r.associated {
			associated = append(associated, r.rtID)
		}
		if r.propagated {
			propagated = append(propagated, r.rtID)
		}
	}

	return associated, propagated, nil
}

func (c *Client) getPropagatedRouteTableIDs(ctx context.Context, tgwID, attachmentID string) ([]string, error) {
	_, propagated, err := c.GetRouteTablesForAttachment(ctx, tgwID, attachmentID)
	return propagated, err
}

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

func (c *Client) GetTGWPeeringAttachment(ctx context.Context, attachmentID string) (*domain.TGWPeeringAttachmentData, error) {
	out, err := c.ec2Client.DescribeTransitGatewayPeeringAttachments(ctx, &ec2.DescribeTransitGatewayPeeringAttachmentsInput{
		TransitGatewayAttachmentIds: []string{attachmentID},
	})
	if err != nil {
		return nil, fmt.Errorf("describe tgw peering attachment %s: %w", attachmentID, err)
	}
	if len(out.TransitGatewayPeeringAttachments) == 0 {
		return nil, fmt.Errorf("tgw peering attachment %s not found", attachmentID)
	}
	peering := &out.TransitGatewayPeeringAttachments[0]
	return &domain.TGWPeeringAttachmentData{
		ID:                   derefString(peering.TransitGatewayAttachmentId),
		TransitGatewayID:     derefString(peering.RequesterTgwInfo.TransitGatewayId),
		PeerTransitGatewayID: derefString(peering.AccepterTgwInfo.TransitGatewayId),
		PeerAccountID:        derefString(peering.AccepterTgwInfo.OwnerId),
	}, nil
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

func parseNLBNameFromDescription(desc string) string {
	// Expected "ELB net/<name>/<id>"
	parts := strings.Split(desc, "/")
	if len(parts) >= 3 && strings.Contains(desc, "net/") {
		return parts[len(parts)-2]
	}
	return ""
}

func parseCLBNameFromDescription(desc string) string {
	// Expected "ELB <name>"
	if strings.HasPrefix(desc, "ELB ") && len(desc) > 4 {
		return desc[4:]
	}
	return ""
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

func (c *Client) GetALB(ctx context.Context, albARN string) (*domain.ALBData, error) {
	out, err := c.elbv2Client.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{
		LoadBalancerArns: []string{albARN},
	})
	if err != nil {
		return nil, fmt.Errorf("describe alb %s: %w", albARN, err)
	}
	if len(out.LoadBalancers) == 0 {
		return nil, fmt.Errorf("alb %s not found", albARN)
	}

	lb := &out.LoadBalancers[0]
	if lb.Type != elbv2types.LoadBalancerTypeEnumApplication {
		return nil, fmt.Errorf("load balancer %s is not an ALB", albARN)
	}

	tgARNs, err := c.getTargetGroupARNsForLB(ctx, albARN)
	if err != nil {
		return nil, err
	}

	return toALBData(lb, tgARNs), nil
}

func (c *Client) GetALBByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.ALBData, error) {
	paginator := elbv2.NewDescribeLoadBalancersPaginator(c.elbv2Client, &elbv2.DescribeLoadBalancersInput{})
	loadBalancers, err := CollectPages(
		ctx,
		paginator.HasMorePages,
		func(ctx context.Context) (*elbv2.DescribeLoadBalancersOutput, error) {
			return paginator.NextPage(ctx)
		},
		func(out *elbv2.DescribeLoadBalancersOutput) []elbv2types.LoadBalancer {
			return out.LoadBalancers
		},
	)
	if err != nil {
		return nil, fmt.Errorf("describe load balancers: %w", err)
	}
	for _, lb := range loadBalancers {
		if lb.Type != elbv2types.LoadBalancerTypeEnumApplication {
			continue
		}
		data := toALBData(&lb, nil)
		if data == nil || data.VPCID != vpcID {
			continue
		}
	}
	return nil, nil
}

func (c *Client) GetNLB(ctx context.Context, nlbARN string) (*domain.NLBData, error) {
	out, err := c.elbv2Client.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{
		LoadBalancerArns: []string{nlbARN},
	})
	if err != nil {
		return nil, fmt.Errorf("describe nlb %s: %w", nlbARN, err)
	}
	if len(out.LoadBalancers) == 0 {
		return nil, fmt.Errorf("nlb %s not found", nlbARN)
	}

	lb := &out.LoadBalancers[0]
	if lb.Type != elbv2types.LoadBalancerTypeEnumNetwork {
		return nil, fmt.Errorf("load balancer %s is not an NLB", nlbARN)
	}

	tgARNs, err := c.getTargetGroupARNsForLB(ctx, nlbARN)
	if err != nil {
		return nil, err
	}

	return toNLBData(lb, tgARNs), nil
}

func (c *Client) GetNLBByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.NLBData, error) {
	eniOut, err := c.ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("private-ip-address"), Values: []string{ip}},
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe network interfaces for nlb ip %s: %w", ip, err)
	}
	for _, eni := range eniOut.NetworkInterfaces {
		if eni.InterfaceType != ec2types.NetworkInterfaceTypeNetworkLoadBalancer {
			continue
		}
		// Parse LB name from description: "ELB net/<name>/<id>"
		desc := derefString(eni.Description)
		name := parseNLBNameFromDescription(desc)
		if name == "" {
			continue
		}
		lbOut, err := c.elbv2Client.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{
			Names: []string{name},
		})
		if err != nil || len(lbOut.LoadBalancers) == 0 {
			continue
		}
		lb := lbOut.LoadBalancers[0]
		if lb.VpcId != nil && *lb.VpcId != vpcID {
			continue
		}
		return toNLBData(&lb, nil), nil
	}
	return nil, nil
}

func (c *Client) GetGWLB(ctx context.Context, gwlbARN string) (*domain.GWLBData, error) {
	out, err := c.elbv2Client.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{
		LoadBalancerArns: []string{gwlbARN},
	})
	if err != nil {
		return nil, fmt.Errorf("describe gwlb %s: %w", gwlbARN, err)
	}
	if len(out.LoadBalancers) == 0 {
		return nil, fmt.Errorf("gwlb %s not found", gwlbARN)
	}

	lb := &out.LoadBalancers[0]
	if lb.Type != elbv2types.LoadBalancerTypeEnumGateway {
		return nil, fmt.Errorf("load balancer %s is not a GWLB", gwlbARN)
	}

	tgARNs, err := c.getTargetGroupARNsForLB(ctx, gwlbARN)
	if err != nil {
		return nil, err
	}

	return toGWLBData(lb, tgARNs), nil
}

func (c *Client) getTargetGroupARNsForLB(ctx context.Context, lbARN string) ([]string, error) {
	out, err := c.elbv2Client.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
		LoadBalancerArn: aws.String(lbARN),
	})
	if err != nil {
		return nil, fmt.Errorf("describe listeners for %s: %w", lbARN, err)
	}

	tgMap := make(map[string]bool)
	for _, listener := range out.Listeners {
		for _, action := range listener.DefaultActions {
			if action.TargetGroupArn != nil {
				tgMap[*action.TargetGroupArn] = true
			}
			if action.ForwardConfig != nil {
				for _, tgTuple := range action.ForwardConfig.TargetGroups {
					if tgTuple.TargetGroupArn != nil {
						tgMap[*tgTuple.TargetGroupArn] = true
					}
				}
			}
		}
	}

	var tgARNs []string
	for arn := range tgMap {
		tgARNs = append(tgARNs, arn)
	}
	return tgARNs, nil
}

func (c *Client) GetCLB(ctx context.Context, clbName string) (*domain.CLBData, error) {
	out, err := c.elbClient.DescribeLoadBalancers(ctx, &elb.DescribeLoadBalancersInput{
		LoadBalancerNames: []string{clbName},
	})
	if err != nil {
		return nil, fmt.Errorf("describe clb %s: %w", clbName, err)
	}
	if len(out.LoadBalancerDescriptions) == 0 {
		return nil, fmt.Errorf("clb %s not found", clbName)
	}

	return toCLBData(&out.LoadBalancerDescriptions[0]), nil
}

func (c *Client) GetCLBByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.CLBData, error) {
	eniOut, err := c.ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("private-ip-address"), Values: []string{ip}},
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe network interfaces for clb ip %s: %w", ip, err)
	}
	for _, eni := range eniOut.NetworkInterfaces {
		desc := derefString(eni.Description)
		name := parseCLBNameFromDescription(desc)
		if name == "" {
			continue
		}
		lbOut, err := c.elbClient.DescribeLoadBalancers(ctx, &elb.DescribeLoadBalancersInput{
			LoadBalancerNames: []string{name},
		})
		if err != nil || len(lbOut.LoadBalancerDescriptions) == 0 {
			continue
		}
		lb := lbOut.LoadBalancerDescriptions[0]
		if lb.VPCId != nil && *lb.VPCId != vpcID {
			continue
		}
		return toCLBData(&lb), nil
	}
	return nil, nil
}

func (c *Client) GetTargetGroup(ctx context.Context, tgARN string) (*domain.TargetGroupData, error) {
	out, err := c.elbv2Client.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
		TargetGroupArns: []string{tgARN},
	})
	if err != nil {
		return nil, fmt.Errorf("describe target group %s: %w", tgARN, err)
	}
	if len(out.TargetGroups) == 0 {
		return nil, fmt.Errorf("target group %s not found", tgARN)
	}

	tg := &out.TargetGroups[0]

	healthOut, err := c.elbv2Client.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{
		TargetGroupArn: aws.String(tgARN),
	})
	if err != nil {
		return nil, fmt.Errorf("describe target health for %s: %w", tgARN, err)
	}

	return toTargetGroupData(tg, healthOut.TargetHealthDescriptions), nil
}

func (c *Client) cacheKey(parts ...string) string {
	return strings.Join(parts, ":")
}

func (c *Client) GetAPIGatewayREST(ctx context.Context, apiID string) (*domain.APIGatewayData, error) {
	key := c.cacheKey("apigw-rest", apiID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.APIGatewayData), nil
	}

	out, err := c.apigwClient.GetRestApi(ctx, &apigateway.GetRestApiInput{
		RestApiId: aws.String(apiID),
	})
	if err != nil {
		return nil, fmt.Errorf("get rest api %s: %w", apiID, err)
	}

	endpointType := "REGIONAL"
	if out.EndpointConfiguration != nil && len(out.EndpointConfiguration.Types) > 0 {
		endpointType = string(out.EndpointConfiguration.Types[0])
	}

	var vpceIDs []string
	if out.EndpointConfiguration != nil {
		vpceIDs = out.EndpointConfiguration.VpcEndpointIds
	}

	data := &domain.APIGatewayData{
		ID:             derefString(out.Id),
		Name:           derefString(out.Name),
		APIType:        "REST",
		EndpointType:   endpointType,
		VPCEndpointIDs: vpceIDs,
	}

	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetAPIGatewayHTTP(ctx context.Context, apiID string) (*domain.APIGatewayData, error) {
	key := c.cacheKey("apigw-http", apiID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.APIGatewayData), nil
	}

	out, err := c.apigwv2Client.GetApi(ctx, &apigatewayv2.GetApiInput{
		ApiId: aws.String(apiID),
	})
	if err != nil {
		return nil, fmt.Errorf("get http api %s: %w", apiID, err)
	}

	apiType := string(out.ProtocolType)

	data := &domain.APIGatewayData{
		ID:           derefString(out.ApiId),
		Name:         derefString(out.Name),
		APIType:      apiType,
		EndpointType: "REGIONAL",
	}

	integrationsOut, err := c.apigwv2Client.GetIntegrations(ctx, &apigatewayv2.GetIntegrationsInput{
		ApiId: aws.String(apiID),
	})
	if err == nil {
		vpcLinkMap := make(map[string][]string)
		for _, integ := range integrationsOut.Items {
			if integ.ConnectionId != nil && *integ.ConnectionId != "" {
				connectionID := *integ.ConnectionId
				if _, exists := vpcLinkMap[connectionID]; !exists {
					vpcLinkMap[connectionID] = []string{}
				}
				if integ.IntegrationUri != nil && *integ.IntegrationUri != "" {
					vpcLinkMap[connectionID] = append(vpcLinkMap[connectionID], *integ.IntegrationUri)
				}
			}
		}
		for id, targets := range vpcLinkMap {
			data.VPCLinkIDs = append(data.VPCLinkIDs, id)
			c.cacheIntegrationTargets(id, targets)
		}
	}

	c.cache.set(key, data)
	return data, nil
}

func (c *Client) cacheIntegrationTargets(vpcLinkID string, targets []string) {
	key := c.cacheKey("vpclink-targets", vpcLinkID)
	c.cache.set(key, targets)
}

func (c *Client) getIntegrationTargets(vpcLinkID string) []string {
	key := c.cacheKey("vpclink-targets", vpcLinkID)
	if v, ok := c.cache.get(key); ok {
		return v.([]string)
	}
	return nil
}

func (c *Client) GetVPCLinkV1(ctx context.Context, vpcLinkID string) (*domain.VPCLinkData, error) {
	key := c.cacheKey("vpclink-v1", vpcLinkID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.VPCLinkData), nil
	}

	out, err := c.apigwClient.GetVpcLink(ctx, &apigateway.GetVpcLinkInput{
		VpcLinkId: aws.String(vpcLinkID),
	})
	if err != nil {
		return nil, fmt.Errorf("get vpc link v1 %s: %w", vpcLinkID, err)
	}

	data := &domain.VPCLinkData{
		ID:         derefString(out.Id),
		Name:       derefString(out.Name),
		Version:    "V1",
		TargetARNs: out.TargetArns,
		Status:     string(out.Status),
	}

	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetVPCLinkV2(ctx context.Context, vpcLinkID string) (*domain.VPCLinkData, error) {
	key := c.cacheKey("vpclink-v2", vpcLinkID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.VPCLinkData), nil
	}

	out, err := c.apigwv2Client.GetVpcLink(ctx, &apigatewayv2.GetVpcLinkInput{
		VpcLinkId: aws.String(vpcLinkID),
	})
	if err != nil {
		return nil, fmt.Errorf("get vpc link v2 %s: %w", vpcLinkID, err)
	}

	var vpcID string
	if len(out.SubnetIds) > 0 {
		subnetOut, err := c.ec2Client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			SubnetIds: []string{out.SubnetIds[0]},
		})
		if err == nil && len(subnetOut.Subnets) > 0 {
			vpcID = derefString(subnetOut.Subnets[0].VpcId)
		}
	}

	data := &domain.VPCLinkData{
		ID:                 derefString(out.VpcLinkId),
		Name:               derefString(out.Name),
		Version:            "V2",
		SubnetIDs:          out.SubnetIds,
		SecurityGroups:     out.SecurityGroupIds,
		Status:             string(out.VpcLinkStatus),
		VPCID:              vpcID,
		IntegrationTargets: c.getIntegrationTargets(vpcLinkID),
	}

	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetAPIGatewayByVPCEndpoint(ctx context.Context, vpceID string) (*domain.APIGatewayData, error) {
	key := c.cacheKey("apigw-by-vpce", vpceID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.APIGatewayData), nil
	}

	paginator := apigateway.NewGetRestApisPaginator(c.apigwClient, &apigateway.GetRestApisInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("get rest apis: %w", err)
		}
		for _, api := range page.Items {
			if api.EndpointConfiguration != nil {
				for _, configuredVPCE := range api.EndpointConfiguration.VpcEndpointIds {
					if configuredVPCE == vpceID {
						endpointType := "REGIONAL"
						if len(api.EndpointConfiguration.Types) > 0 {
							endpointType = string(api.EndpointConfiguration.Types[0])
						}
						data := &domain.APIGatewayData{
							ID:             derefString(api.Id),
							Name:           derefString(api.Name),
							APIType:        "REST",
							EndpointType:   endpointType,
							VPCEndpointIDs: api.EndpointConfiguration.VpcEndpointIds,
						}
						c.cache.set(key, data)
						return data, nil
					}
				}
			}
		}
	}

	var nextToken *string
	for {
		apisOut, err := c.apigwv2Client.GetApis(ctx, &apigatewayv2.GetApisInput{
			NextToken: nextToken,
		})
		if err != nil {
			break
		}
		for _, api := range apisOut.Items {
			apiID := derefString(api.ApiId)
			integrationsOut, err := c.apigwv2Client.GetIntegrations(ctx, &apigatewayv2.GetIntegrationsInput{
				ApiId: aws.String(apiID),
			})
			if err != nil {
				continue
			}

			var vpcLinkIDs []string
			vpcLinkMap := make(map[string]bool)
			for _, integ := range integrationsOut.Items {
				if integ.ConnectionId != nil && *integ.ConnectionId != "" {
					vpcLinkMap[*integ.ConnectionId] = true
				}
			}
			for id := range vpcLinkMap {
				vpcLinkV2, err := c.GetVPCLinkV2(ctx, id)
				if err != nil {
					continue
				}
				if vpcLinkV2.VPCID != "" {
					vpceOut, err := c.ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
						VpcEndpointIds: []string{vpceID},
					})
					if err == nil && len(vpceOut.VpcEndpoints) > 0 {
						vpce := vpceOut.VpcEndpoints[0]
						if derefString(vpce.VpcId) == vpcLinkV2.VPCID {
							vpcLinkIDs = append(vpcLinkIDs, id)
						}
					}
				}
			}

			if len(vpcLinkIDs) > 0 {
				data := &domain.APIGatewayData{
					ID:           apiID,
					Name:         derefString(api.Name),
					APIType:      string(api.ProtocolType),
					EndpointType: "REGIONAL",
					VPCLinkIDs:   vpcLinkIDs,
				}
				c.cache.set(key, data)
				return data, nil
			}
		}
		if apisOut.NextToken == nil {
			break
		}
		nextToken = apisOut.NextToken
	}

	return nil, nil
}

func (c *Client) GetAPIGatewayByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.APIGatewayData, error) {
	eniOut, err := c.ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("private-ip-address"), Values: []string{ip}},
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe network interfaces for apigw ip %s: %w", ip, err)
	}

	for _, eni := range eniOut.NetworkInterfaces {
		if eni.InterfaceType != ec2types.NetworkInterfaceTypeVpcEndpoint {
			continue
		}

		var vpceID string
		if eni.Attachment != nil && eni.Attachment.InstanceId != nil {
			vpceID = derefString(eni.Attachment.InstanceId)
		}

		if vpceID == "" || !strings.HasPrefix(vpceID, "vpce-") {
			desc := derefString(eni.Description)
			if idx := strings.Index(desc, "vpce-"); idx >= 0 {
				endIdx := idx
				for endIdx < len(desc) && desc[endIdx] != ' ' && desc[endIdx] != ')' {
					endIdx++
				}
				vpceID = desc[idx:endIdx]
			}
		}

		if vpceID == "" || !strings.HasPrefix(vpceID, "vpce-") {
			continue
		}

		vpceOut, err := c.ec2Client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
			VpcEndpointIds: []string{vpceID},
		})
		if err != nil || len(vpceOut.VpcEndpoints) == 0 {
			continue
		}

		vpce := vpceOut.VpcEndpoints[0]
		serviceName := derefString(vpce.ServiceName)
		if !strings.Contains(serviceName, "execute-api") {
			continue
		}

		apigwData, err := c.GetAPIGatewayByVPCEndpoint(ctx, vpceID)
		if err == nil && apigwData != nil {
			apigwData.PrivateIPs = append(apigwData.PrivateIPs, ip)
			return apigwData, nil
		}
	}

	return nil, nil
}

func (c *Client) GetEKSPodByIP(ctx context.Context, ip, vpcID string) (*domain.EKSPodData, error) {
	out, err := c.ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("vpc-id"), Values: []string{vpcID}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe network interfaces for eks pod ip %s: %w", ip, err)
	}

	for _, eni := range out.NetworkInterfaces {
		desc := derefString(eni.Description)
		if !strings.Contains(desc, "aws-K8S-") && !strings.Contains(desc, "amazon-vpc-cni") {
			continue
		}

		for _, privateIPAddr := range eni.PrivateIpAddresses {
			if derefString(privateIPAddr.PrivateIpAddress) == ip {
				var sgs []string
				for _, sg := range eni.Groups {
					sgs = append(sgs, derefString(sg.GroupId))
				}

				return &domain.EKSPodData{
					PodIP:          ip,
					HostIP:         derefString(eni.PrivateIpAddress),
					ENIID:          derefString(eni.NetworkInterfaceId),
					SecurityGroups: sgs,
					SubnetID:       derefString(eni.SubnetId),
				}, nil
			}
		}
	}

	return nil, nil
}

func (c *Client) GetElastiCacheCluster(ctx context.Context, clusterID string) (*domain.ElastiCacheClusterData, error) {
	key := c.cacheKey("elasticache", clusterID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.ElastiCacheClusterData), nil
	}

	out, err := c.elasticacheClient.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{
		CacheClusterId:    aws.String(clusterID),
		ShowCacheNodeInfo: aws.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("describe elasticache cluster %s: %w", clusterID, err)
	}
	if len(out.CacheClusters) == 0 {
		return nil, fmt.Errorf("elasticache cluster %s not found", clusterID)
	}

	cluster := &out.CacheClusters[0]
	data := toElastiCacheClusterData(cluster)

	if cluster.CacheSubnetGroupName != nil {
		subnetOut, err := c.elasticacheClient.DescribeCacheSubnetGroups(ctx, &elasticache.DescribeCacheSubnetGroupsInput{
			CacheSubnetGroupName: cluster.CacheSubnetGroupName,
		})
		if err == nil && len(subnetOut.CacheSubnetGroups) > 0 {
			for _, subnet := range subnetOut.CacheSubnetGroups[0].Subnets {
				if subnet.SubnetIdentifier != nil {
					data.SubnetIDs = append(data.SubnetIDs, *subnet.SubnetIdentifier)
				}
			}
			if subnetOut.CacheSubnetGroups[0].VpcId != nil {
				data.VPCID = *subnetOut.CacheSubnetGroups[0].VpcId
			}
		}
	}

	c.cache.set(key, data)
	return data, nil
}

func (c *Client) GetElastiCacheClusterByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.ElastiCacheClusterData, error) {
	paginator := elasticache.NewDescribeCacheClustersPaginator(c.elasticacheClient, &elasticache.DescribeCacheClustersInput{
		ShowCacheNodeInfo: aws.Bool(true),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe elasticache clusters: %w", err)
		}

		for _, cluster := range page.CacheClusters {
			for _, node := range cluster.CacheNodes {
				if node.Endpoint != nil && node.Endpoint.Address != nil {
					eniOut, err := c.ec2Client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
						Filters: []ec2types.Filter{
							{Name: aws.String("private-ip-address"), Values: []string{ip}},
							{Name: aws.String("vpc-id"), Values: []string{vpcID}},
							{Name: aws.String("requester-id"), Values: []string{"amazon-elasticache"}},
						},
					})
					if err == nil && len(eniOut.NetworkInterfaces) > 0 {
						return c.GetElastiCacheCluster(ctx, *cluster.CacheClusterId)
					}
				}
			}
		}
	}

	return nil, nil
}

func (c *Client) GetDirectConnectGatewayAttachments(ctx context.Context, dxgwID string) ([]domain.TGWAttachmentData, error) {
	key := c.cacheKey("dxgw-attachments", dxgwID)
	if v, ok := c.cache.get(key); ok {
		return v.([]domain.TGWAttachmentData), nil
	}

	out, err := c.directconnectClient.DescribeDirectConnectGatewayAttachments(ctx, &directconnect.DescribeDirectConnectGatewayAttachmentsInput{
		DirectConnectGatewayId: aws.String(dxgwID),
	})
	if err != nil {
		return nil, fmt.Errorf("describe direct connect gateway attachments for %s: %w", dxgwID, err)
	}

	var attachments []domain.TGWAttachmentData
	for _, att := range out.DirectConnectGatewayAttachments {
		if att.VirtualInterfaceId != nil {
			continue
		}

		tgwID := ""
		if att.VirtualInterfaceOwnerAccount != nil {
			tgwID = derefString(att.VirtualInterfaceOwnerAccount)
		}

		attachments = append(attachments, domain.TGWAttachmentData{
			ID:               derefString(att.VirtualInterfaceId),
			TransitGatewayID: tgwID,
			State:            string(att.AttachmentState),
		})
	}

	c.cache.set(key, attachments)
	return attachments, nil
}

func (c *Client) GetNetworkFirewall(ctx context.Context, firewallID string) (*domain.NetworkFirewallData, error) {
	key := c.cacheKey("nfw", firewallID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.NetworkFirewallData), nil
	}

	out, err := c.networkFirewallClient.DescribeFirewall(ctx, &networkfirewall.DescribeFirewallInput{
		FirewallArn: aws.String(firewallID),
	})
	if err != nil {
		out, err = c.networkFirewallClient.DescribeFirewall(ctx, &networkfirewall.DescribeFirewallInput{
			FirewallName: aws.String(firewallID),
		})
		if err != nil {
			return nil, fmt.Errorf("describe network firewall %s: %w", firewallID, err)
		}
	}

	if out.Firewall == nil {
		return nil, fmt.Errorf("network firewall %s not found", firewallID)
	}

	fw := out.Firewall
	policyARN := derefString(fw.FirewallPolicyArn)

	var statelessGroups []domain.StatelessRuleGroup
	var statefulGroups []domain.StatefulRuleGroup
	var defaultActions domain.FirewallDefaultActions

	if policyARN != "" {
		policyOut, err := c.networkFirewallClient.DescribeFirewallPolicy(ctx, &networkfirewall.DescribeFirewallPolicyInput{
			FirewallPolicyArn: aws.String(policyARN),
		})
		if err == nil && policyOut.FirewallPolicy != nil {
			policy := policyOut.FirewallPolicy

			for _, action := range policy.StatelessDefaultActions {
				defaultActions.StatelessDefaultActions = append(defaultActions.StatelessDefaultActions, action)
			}
			for _, action := range policy.StatelessFragmentDefaultActions {
				defaultActions.StatelessFragmentDefaultActions = append(defaultActions.StatelessFragmentDefaultActions, action)
			}
			for _, action := range policy.StatefulDefaultActions {
				defaultActions.StatefulDefaultActions = append(defaultActions.StatefulDefaultActions, string(action))
			}

			for _, ref := range policy.StatelessRuleGroupReferences {
				group, err := c.getStatelessRuleGroup(ctx, derefString(ref.ResourceArn))
				if err == nil {
					group.Priority = int(derefInt32(ref.Priority))
					statelessGroups = append(statelessGroups, group)
				}
			}

			for _, ref := range policy.StatefulRuleGroupReferences {
				group, err := c.getStatefulRuleGroup(ctx, derefString(ref.ResourceArn))
				if err == nil {
					group.Priority = int(derefInt32(ref.Priority))
					statefulGroups = append(statefulGroups, group)
				}
			}
		}
	}

	var subnetMappings []domain.FirewallSubnetMapping
	for _, mapping := range fw.SubnetMappings {
		subnetMappings = append(subnetMappings, domain.FirewallSubnetMapping{
			SubnetID: derefString(mapping.SubnetId),
		})
	}

	if out.FirewallStatus != nil {
		for subnetID, sync := range out.FirewallStatus.SyncStates {
			for i := range subnetMappings {
				if subnetMappings[i].SubnetID == subnetID && sync.Attachment != nil {
					subnetMappings[i].EndpointID = derefString(sync.Attachment.EndpointId)
				}
			}
		}
	}

	data := &domain.NetworkFirewallData{
		ID:                  derefString(fw.FirewallArn),
		Name:                derefString(fw.FirewallName),
		PolicyARN:           policyARN,
		VPCID:               derefString(fw.VpcId),
		SubnetMappings:      subnetMappings,
		StatelessRuleGroups: statelessGroups,
		StatefulRuleGroups:  statefulGroups,
		DefaultActions:      defaultActions,
	}

	c.cache.set(key, data)
	return data, nil
}

func (c *Client) getStatelessRuleGroup(ctx context.Context, arn string) (domain.StatelessRuleGroup, error) {
	out, err := c.networkFirewallClient.DescribeRuleGroup(ctx, &networkfirewall.DescribeRuleGroupInput{
		RuleGroupArn: aws.String(arn),
		Type:         nfwtypes.RuleGroupTypeStateless,
	})
	if err != nil {
		return domain.StatelessRuleGroup{}, fmt.Errorf("describe stateless rule group %s: %w", arn, err)
	}

	group := domain.StatelessRuleGroup{
		ARN: arn,
	}

	if out.RuleGroup != nil && out.RuleGroup.RulesSource != nil && out.RuleGroup.RulesSource.StatelessRulesAndCustomActions != nil {
		for _, rule := range out.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules {
			if rule.RuleDefinition == nil {
				continue
			}

			statelessRule := domain.StatelessRule{
				Priority: int(derefInt32(rule.Priority)),
				Actions:  rule.RuleDefinition.Actions,
			}

			if rule.RuleDefinition.MatchAttributes != nil {
				attrs := rule.RuleDefinition.MatchAttributes

				for _, p := range attrs.Protocols {
					statelessRule.Match.Protocols = append(statelessRule.Match.Protocols, int(p))
				}

				for _, src := range attrs.Sources {
					statelessRule.Match.Sources = append(statelessRule.Match.Sources, derefString(src.AddressDefinition))
				}

				for _, dst := range attrs.Destinations {
					statelessRule.Match.Destinations = append(statelessRule.Match.Destinations, derefString(dst.AddressDefinition))
				}

				for _, pr := range attrs.SourcePorts {
					statelessRule.Match.SourcePorts = append(statelessRule.Match.SourcePorts, domain.PortRangeSpec{
						From: int(pr.FromPort),
						To:   int(pr.ToPort),
					})
				}

				for _, pr := range attrs.DestinationPorts {
					statelessRule.Match.DestPorts = append(statelessRule.Match.DestPorts, domain.PortRangeSpec{
						From: int(pr.FromPort),
						To:   int(pr.ToPort),
					})
				}

				for _, tcpFlag := range attrs.TCPFlags {
					var flags, masks []string
					for _, f := range tcpFlag.Flags {
						flags = append(flags, string(f))
					}
					for _, m := range tcpFlag.Masks {
						masks = append(masks, string(m))
					}
					statelessRule.Match.TCPFlags = append(statelessRule.Match.TCPFlags, domain.TCPFlagSpec{
						Flags: flags,
						Masks: masks,
					})
				}
			}

			group.Rules = append(group.Rules, statelessRule)
		}
	}

	return group, nil
}

func (c *Client) getStatefulRuleGroup(ctx context.Context, arn string) (domain.StatefulRuleGroup, error) {
	out, err := c.networkFirewallClient.DescribeRuleGroup(ctx, &networkfirewall.DescribeRuleGroupInput{
		RuleGroupArn: aws.String(arn),
		Type:         nfwtypes.RuleGroupTypeStateful,
	})
	if err != nil {
		return domain.StatefulRuleGroup{}, fmt.Errorf("describe stateful rule group %s: %w", arn, err)
	}

	group := domain.StatefulRuleGroup{
		ARN: arn,
	}

	if out.RuleGroupResponse != nil {
		if out.RuleGroupResponse.Type == nfwtypes.RuleGroupTypeStateful {
			group.RuleOrder = "DEFAULT_ACTION_ORDER"
		}
	}

	if out.RuleGroup != nil && out.RuleGroup.RulesSource != nil {
		if out.RuleGroup.RulesSource.StatefulRules != nil {
			for _, rule := range out.RuleGroup.RulesSource.StatefulRules {
				statefulRule := domain.StatefulRule{
					Action:   string(rule.Action),
					Protocol: string(rule.Header.Protocol),
				}

				if rule.Header != nil {
					statefulRule.Source = derefString(rule.Header.Source)
					statefulRule.SourcePort = derefString(rule.Header.SourcePort)
					statefulRule.Destination = derefString(rule.Header.Destination)
					statefulRule.DestPort = derefString(rule.Header.DestinationPort)
					statefulRule.Direction = string(rule.Header.Direction)
				}

				for _, opt := range rule.RuleOptions {
					if derefString(opt.Keyword) == "sid" && len(opt.Settings) > 0 {
						statefulRule.SID = opt.Settings[0]
					}
				}

				group.Rules = append(group.Rules, statefulRule)
			}
		}
	}

	return group, nil
}

func (c *Client) GetNetworkFirewallByEndpoint(ctx context.Context, endpointID string) (*domain.NetworkFirewallData, error) {
	key := c.cacheKey("nfw-by-endpoint", endpointID)
	if v, ok := c.cache.get(key); ok {
		return v.(*domain.NetworkFirewallData), nil
	}

	paginator := networkfirewall.NewListFirewallsPaginator(c.networkFirewallClient, &networkfirewall.ListFirewallsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list network firewalls: %w", err)
		}

		for _, fw := range page.Firewalls {
			fwData, err := c.GetNetworkFirewall(ctx, derefString(fw.FirewallArn))
			if err != nil {
				continue
			}

			for _, mapping := range fwData.SubnetMappings {
				if mapping.EndpointID == endpointID {
					c.cache.set(key, fwData)
					return fwData, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("network firewall for endpoint %s not found", endpointID)
}
