package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/eleven-am/argus/internal/domain"
)

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
