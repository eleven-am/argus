package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/eleven-am/argus/internal/domain"
)

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
