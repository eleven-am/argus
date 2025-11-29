package components

import (
	"fmt"
	"strings"

	"github.com/eleven-am/argus/internal/domain"
)

type APIGateway struct {
	data      *domain.APIGatewayData
	accountID string
}

func NewAPIGateway(data *domain.APIGatewayData, accountID string) *APIGateway {
	return &APIGateway{
		data:      data,
		accountID: accountID,
	}
}

func (a *APIGateway) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	switch a.data.EndpointType {
	case "EDGE":
		return nil, nil

	case "PRIVATE":
		if len(a.data.VPCEndpointIDs) == 0 {
			return nil, &domain.BlockingError{
				ComponentID: a.GetID(),
				Reason:      "private API has no VPC endpoints configured",
			}
		}
		client, err := analyzerCtx.GetAccountContext().GetClient(a.accountID)
		if err != nil {
			return nil, err
		}
		ctx := analyzerCtx.Context()
		var components []domain.Component
		for _, vpceID := range a.data.VPCEndpointIDs {
			vpceData, err := client.GetVPCEndpoint(ctx, vpceID)
			if err != nil {
				continue
			}
			components = append(components, NewVPCEndpoint(vpceData, a.accountID))
		}
		if len(components) == 0 {
			return nil, &domain.BlockingError{
				ComponentID: a.GetID(),
				Reason:      "no accessible VPC endpoints for private API",
			}
		}
		return components, nil

	case "REGIONAL":
		if len(a.data.VPCLinkIDs) > 0 {
			client, err := analyzerCtx.GetAccountContext().GetClient(a.accountID)
			if err != nil {
				return nil, err
			}
			ctx := analyzerCtx.Context()
			var components []domain.Component
			for _, vpcLinkID := range a.data.VPCLinkIDs {
				var vpcLinkData *domain.VPCLinkData
				var fetchErr error

				if a.data.APIType == "REST" {
					vpcLinkData, fetchErr = client.GetVPCLinkV1(ctx, vpcLinkID)
				} else {
					vpcLinkData, fetchErr = client.GetVPCLinkV2(ctx, vpcLinkID)
				}
				if fetchErr != nil {
					continue
				}
				components = append(components, NewVPCLink(vpcLinkData, a.accountID))
			}
			if len(components) > 0 {
				return components, nil
			}
		}
		return nil, nil

	default:
		return nil, nil
	}
}

func (a *APIGateway) GetRoutingTarget() domain.RoutingTarget {
	if len(a.data.PrivateIPs) > 0 {
		return domain.RoutingTarget{
			IP:       a.data.PrivateIPs[0],
			Port:     443,
			Protocol: "tcp",
		}
	}
	return domain.RoutingTarget{
		Port:     443,
		Protocol: "tcp",
	}
}

func (a *APIGateway) GetID() string {
	return fmt.Sprintf("%s:apigw:%s", a.accountID, a.data.ID)
}

func (a *APIGateway) GetAccountID() string {
	return a.accountID
}

func (a *APIGateway) IsTerminal() bool {
	return a.data.EndpointType == "EDGE" || (a.data.EndpointType == "REGIONAL" && len(a.data.VPCLinkIDs) == 0)
}

func (a *APIGateway) GetComponentType() string {
	return "APIGateway"
}

type VPCLink struct {
	data      *domain.VPCLinkData
	accountID string
}

func NewVPCLink(data *domain.VPCLinkData, accountID string) *VPCLink {
	return &VPCLink{
		data:      data,
		accountID: accountID,
	}
}

func (v *VPCLink) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if v.data.Status != "AVAILABLE" && v.data.Status != "" {
		return nil, &domain.BlockingError{
			ComponentID: v.GetID(),
			Reason:      fmt.Sprintf("VPC link status is %s, not AVAILABLE", v.data.Status),
		}
	}

	client, err := analyzerCtx.GetAccountContext().GetClient(v.accountID)
	if err != nil {
		return nil, err
	}
	ctx := analyzerCtx.Context()

	if v.data.Version == "V1" {
		var components []domain.Component
		for _, targetARN := range v.data.TargetARNs {
			if strings.Contains(targetARN, ":loadbalancer/net/") {
				nlbData, err := client.GetNLB(ctx, targetARN)
				if err != nil {
					continue
				}
				components = append(components, NewNLB(nlbData, v.accountID))
			}
		}
		if len(components) == 0 {
			return nil, &domain.BlockingError{
				ComponentID: v.GetID(),
				Reason:      "no accessible NLB targets for VPC link v1",
			}
		}
		return components, nil
	}

	if v.data.Version == "V2" {
		if len(v.data.SubnetIDs) == 0 {
			return nil, &domain.BlockingError{
				ComponentID: v.GetID(),
				Reason:      "VPC link v2 has no subnets configured",
			}
		}

		var backendComponents []domain.Component
		for _, target := range v.data.IntegrationTargets {
			if nlbARN := extractNLBARNFromTarget(target); nlbARN != "" {
				nlbData, err := client.GetNLB(ctx, nlbARN)
				if err == nil && nlbData != nil {
					backendComponents = append(backendComponents, NewNLB(nlbData, v.accountID))
				}
			} else if albARN := extractALBARNFromTarget(target); albARN != "" {
				albData, err := client.GetALB(ctx, albARN)
				if err == nil && albData != nil {
					backendComponents = append(backendComponents, NewALB(albData, v.accountID))
				}
			}
		}

		if len(backendComponents) > 0 {
			return backendComponents, nil
		}

		var components []domain.Component
		for _, subnetID := range v.data.SubnetIDs {
			subnetData, err := client.GetSubnet(ctx, subnetID)
			if err != nil {
				continue
			}

			var terminal domain.Component = NewSubnet(subnetData, v.accountID)
			for i := len(v.data.SecurityGroups) - 1; i >= 0; i-- {
				sgData, err := client.GetSecurityGroup(ctx, v.data.SecurityGroups[i])
				if err != nil {
					terminal = nil
					break
				}
				terminal = NewSecurityGroupWithNext(sgData, v.accountID, terminal)
			}

			if terminal != nil {
				components = append(components, terminal)
			}
		}

		if len(components) == 0 {
			return nil, &domain.BlockingError{
				ComponentID: v.GetID(),
				Reason:      "no accessible subnets/security groups for VPC link v2",
			}
		}

		return components, nil
	}

	return nil, &domain.BlockingError{
		ComponentID: v.GetID(),
		Reason:      fmt.Sprintf("unknown VPC link version: %s", v.data.Version),
	}
}

func (v *VPCLink) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (v *VPCLink) GetID() string {
	return fmt.Sprintf("%s:vpclink:%s", v.accountID, v.data.ID)
}

func (v *VPCLink) GetAccountID() string {
	return v.accountID
}

func (v *VPCLink) GetComponentType() string {
	return "VPCLink"
}

func extractNLBARNFromTarget(target string) string {
	if strings.HasPrefix(target, "arn:aws:elasticloadbalancing:") && strings.Contains(target, ":loadbalancer/net/") {
		return target
	}
	return ""
}

func extractALBARNFromTarget(target string) string {
	if strings.HasPrefix(target, "arn:aws:elasticloadbalancing:") && strings.Contains(target, ":loadbalancer/app/") {
		return target
	}
	return ""
}
