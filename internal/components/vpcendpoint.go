package components

import (
	"fmt"
	"strings"

	"github.com/eleven-am/argus/internal/domain"
)

type VPCEndpoint struct {
	data      *domain.VPCEndpointData
	accountID string
}

func NewVPCEndpoint(data *domain.VPCEndpointData, accountID string) *VPCEndpoint {
	return &VPCEndpoint{
		data:      data,
		accountID: accountID,
	}
}

func (ve *VPCEndpoint) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if ve.data.State != "" && ve.data.State != "available" {
		return nil, &domain.BlockingError{
			ComponentID: ve.GetID(),
			Reason:      fmt.Sprintf("vpc endpoint state is %s, not available", ve.data.State),
		}
	}

	if dest.IP == "" {
		return nil, &domain.BlockingError{
			ComponentID: ve.GetID(),
			Reason:      "vpc endpoint requires a destination IP",
		}
	}

	if !policyAllows(dest.IP, ve.data.PolicyJSON) {
		return nil, &domain.BlockingError{
			ComponentID: ve.GetID(),
			Reason:      "vpc endpoint policy denies destination IP",
		}
	}

	if ve.data.Type == "Interface" {
		if analyzerCtx == nil {
			return nil, &domain.BlockingError{
				ComponentID: ve.GetID(),
				Reason:      "analyzer context is required to resolve interface endpoint security groups",
			}
		}
		client, err := analyzerCtx.GetAccountContext().GetClient(ve.accountID)
		if err != nil {
			return nil, err
		}

		ctx := analyzerCtx.Context()

		if ve.isExecuteAPIEndpoint() {
			apigwData, err := client.GetAPIGatewayByVPCEndpoint(ctx, ve.data.ID)
			if err == nil && apigwData != nil {
				return []domain.Component{NewAPIGateway(apigwData, ve.accountID)}, nil
			}
		}

		if len(ve.data.SubnetIDs) == 0 {
			return nil, &domain.BlockingError{
				ComponentID: ve.GetID(),
				Reason:      "interface endpoint missing subnet associations",
			}
		}

		var components []domain.Component
		for _, subnetID := range ve.data.SubnetIDs {
			subnetData, err := client.GetSubnet(ctx, subnetID)
			if err != nil {
				continue
			}
			subnet := NewSubnet(subnetData, ve.accountID)

			var terminal domain.Component = subnet
			for i := len(ve.data.SecurityGroups) - 1; i >= 0; i-- {
				sgData, err := client.GetSecurityGroup(ctx, ve.data.SecurityGroups[i])
				if err != nil {
					terminal = nil
					break
				}
				terminal = NewSecurityGroupWithNext(sgData, ve.accountID, terminal)
			}

			if terminal != nil {
				components = append(components, terminal)
			}
		}

		if len(components) == 0 {
			return nil, &domain.BlockingError{
				ComponentID: ve.GetID(),
				Reason:      "no accessible subnets/security groups for interface endpoint",
			}
		}

		return components, nil
	}

	return []domain.Component{NewIPTarget(&domain.IPTargetData{IP: dest.IP, Port: dest.Port}, ve.accountID)}, nil
}

func (ve *VPCEndpoint) isExecuteAPIEndpoint() bool {
	return strings.Contains(ve.data.ServiceName, "execute-api")
}

func (ve *VPCEndpoint) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (ve *VPCEndpoint) GetID() string {
	return fmt.Sprintf("%s:%s", ve.accountID, ve.data.ID)
}

func (ve *VPCEndpoint) GetAccountID() string {
	return ve.accountID
}
