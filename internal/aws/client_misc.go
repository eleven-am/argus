package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directconnect"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	nfwtypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"

	"github.com/eleven-am/argus/internal/domain"
)

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
		attachments = append(attachments, domain.TGWAttachmentData{
			ID:               derefString(att.VirtualInterfaceId),
			TransitGatewayID: "",
			TGWAccountID:     derefString(att.VirtualInterfaceOwnerAccount),
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
