package argus

import (
	"context"
	"fmt"
	"strings"

	internalaws "github.com/eleven-am/argus/internal/aws"
	"github.com/eleven-am/argus/internal/components"
	"github.com/eleven-am/argus/internal/domain"
)

type AccountContext = internalaws.AccountContext

type ReachabilityResult = domain.ReachabilityResult

type PathTrace = domain.PathTrace

type ComponentHop = domain.ComponentHop

type HopAction = domain.HopAction

const (
	HopActionAllowed   = domain.HopActionAllowed
	HopActionBlocked   = domain.HopActionBlocked
	HopActionRouted    = domain.HopActionRouted
	HopActionForwarded = domain.HopActionForwarded
	HopActionResolved  = domain.HopActionResolved
	HopActionTerminal  = domain.HopActionTerminal
	HopActionEntered   = domain.HopActionEntered
)

type HopLineage = domain.HopLineage

type AllPathsResult = domain.AllPathsResult

type RuleEvaluation = domain.RuleEvaluation

type EvaluationResult = domain.EvaluationResult

type resourceType int

const (
	resourceTypeEC2 resourceType = iota
	resourceTypeRDS
	resourceTypeLambda
	resourceTypeElastiCache
	resourceTypeALB
	resourceTypeNLB
	resourceTypeCLB
	resourceTypeGWLB
	resourceTypeEKSPod
	resourceTypeAPIGatewayREST
	resourceTypeAPIGatewayHTTP
	resourceTypeVPCEndpoint
	resourceTypeNetworkInterface
	resourceTypeDirectConnectOnPrem
	resourceTypeGWLBEndpoint
	resourceTypeIPTarget
	resourceTypeInternetGateway
	resourceTypeNATGateway
	resourceTypeDirectConnectGateway
	resourceTypeCarrierGateway
	resourceTypeLocalGateway
)

type ResourceRef struct {
	accountID    string
	resourceID   string
	resourceType resourceType
}

// EC2 creates a reference to an EC2 instance.
// Use the instance ID (e.g., "i-0abc123def456").
func EC2(accountID, instanceID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: instanceID, resourceType: resourceTypeEC2}
}

// RDS creates a reference to an RDS database instance.
// Use the DB instance identifier (e.g., "my-database").
func RDS(accountID, dbIdentifier string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: dbIdentifier, resourceType: resourceTypeRDS}
}

// Lambda creates a reference to a Lambda function.
// Use the function name or ARN.
func Lambda(accountID, functionName string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: functionName, resourceType: resourceTypeLambda}
}

// ElastiCache creates a reference to an ElastiCache cluster.
// Use the cluster ID (e.g., "my-redis-cluster").
func ElastiCache(accountID, clusterID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: clusterID, resourceType: resourceTypeElastiCache}
}

// ALB creates a reference to an Application Load Balancer.
// Use the full ALB ARN.
func ALB(accountID, albARN string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: albARN, resourceType: resourceTypeALB}
}

// NLB creates a reference to a Network Load Balancer.
// Use the full NLB ARN.
func NLB(accountID, nlbARN string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: nlbARN, resourceType: resourceTypeNLB}
}

// CLB creates a reference to a Classic Load Balancer.
// Use the load balancer name.
func CLB(accountID, clbName string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: clbName, resourceType: resourceTypeCLB}
}

// GWLB creates a reference to a Gateway Load Balancer.
// Use the full GWLB ARN.
func GWLB(accountID, gwlbARN string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: gwlbARN, resourceType: resourceTypeGWLB}
}

// EKSPod creates a reference to an EKS pod by its IP address.
// Requires the VPC ID where the pod runs and the pod's IP address.
func EKSPod(accountID, vpcID, podIP string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: vpcID + "/" + podIP, resourceType: resourceTypeEKSPod}
}

// APIGatewayREST creates a reference to a REST API Gateway.
// Use the API ID (e.g., "abc123def4").
func APIGatewayREST(accountID, apiID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: apiID, resourceType: resourceTypeAPIGatewayREST}
}

// APIGatewayHTTP creates a reference to an HTTP API Gateway (v2).
// Use the API ID (e.g., "abc123def4").
func APIGatewayHTTP(accountID, apiID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: apiID, resourceType: resourceTypeAPIGatewayHTTP}
}

// VPCEndpoint creates a reference to a VPC Endpoint (Interface or Gateway type).
// Use the VPC endpoint ID (e.g., "vpce-0abc123").
func VPCEndpoint(accountID, vpceID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: vpceID, resourceType: resourceTypeVPCEndpoint}
}

// NetworkInterface creates a reference to an Elastic Network Interface.
// Use the ENI ID (e.g., "eni-0abc123").
func NetworkInterface(accountID, eniID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: eniID, resourceType: resourceTypeNetworkInterface}
}

// OnPremDirectConnect creates a reference to an on-premises source via Direct Connect.
// Use the Direct Connect Gateway ID and the on-prem source IP address.
func OnPremDirectConnect(accountID, dxgwID, sourceIP string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: dxgwID + "/" + sourceIP, resourceType: resourceTypeDirectConnectOnPrem}
}

// GWLBEndpoint creates a reference to a Gateway Load Balancer Endpoint.
// Use the VPC endpoint ID (e.g., "vpce-0abc123").
func GWLBEndpoint(accountID, vpceID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: vpceID, resourceType: resourceTypeGWLBEndpoint}
}

// ExternalIP creates a reference to an external IP address (e.g., internet destination).
// Use for testing connectivity to public IPs like "8.8.8.8" on a specific port.
func ExternalIP(ip string, port int) ResourceRef {
	return ResourceRef{accountID: "", resourceID: fmt.Sprintf("%s/%d", ip, port), resourceType: resourceTypeIPTarget}
}

// InternetGateway creates a reference to an Internet Gateway.
// Use the IGW ID (e.g., "igw-0abc123").
func InternetGateway(accountID, igwID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: igwID, resourceType: resourceTypeInternetGateway}
}

// NATGateway creates a reference to a NAT Gateway.
// Use the NAT gateway ID (e.g., "nat-0abc123").
func NATGateway(accountID, natID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: natID, resourceType: resourceTypeNATGateway}
}

// DirectConnectGateway creates a reference to a Direct Connect Gateway.
// Use the DX gateway ID (e.g., "dxgw-0abc123").
func DirectConnectGateway(accountID, dxgwID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: dxgwID, resourceType: resourceTypeDirectConnectGateway}
}

// CarrierGateway creates a reference to a Carrier Gateway (for Wavelength Zones).
// Use the carrier gateway ID (e.g., "cagw-0abc123").
func CarrierGateway(accountID, cgwID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: cgwID, resourceType: resourceTypeCarrierGateway}
}

// LocalGateway creates a reference to a Local Gateway (for Outposts).
// Use the local gateway ID (e.g., "lgw-0abc123").
func LocalGateway(accountID, lgwID string) ResourceRef {
	return ResourceRef{accountID: accountID, resourceID: lgwID, resourceType: resourceTypeLocalGateway}
}

func (r ResourceRef) resolve(ctx context.Context, accountCtx *AccountContext) (domain.Component, error) {
	if r.resourceType == resourceTypeIPTarget {
		parts := splitResourceID(r.resourceID, 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid IP target resource ID format, expected ip/port")
		}
		ip := parts[0]
		var port int
		fmt.Sscanf(parts[1], "%d", &port)
		data := &domain.IPTargetData{
			IP:   ip,
			Port: port,
		}
		return components.NewIPTarget(data, ""), nil
	}

	client, err := accountCtx.GetClient(r.accountID)
	if err != nil {
		return nil, err
	}

	switch r.resourceType {
	case resourceTypeEC2:
		data, err := client.GetEC2Instance(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewEC2Instance(data, r.accountID), nil

	case resourceTypeRDS:
		data, err := client.GetRDSInstance(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewRDSInstance(data, r.accountID), nil

	case resourceTypeLambda:
		data, err := client.GetLambdaFunction(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewLambdaFunction(data, r.accountID), nil

	case resourceTypeElastiCache:
		data, err := client.GetElastiCacheCluster(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewElastiCacheCluster(data, r.accountID), nil

	case resourceTypeALB:
		data, err := client.GetALB(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewALB(data, r.accountID), nil

	case resourceTypeNLB:
		data, err := client.GetNLB(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewNLB(data, r.accountID), nil

	case resourceTypeCLB:
		data, err := client.GetCLB(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewCLB(data, r.accountID), nil

	case resourceTypeGWLB:
		data, err := client.GetGWLB(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewGWLB(data, r.accountID), nil

	case resourceTypeEKSPod:
		parts := splitResourceID(r.resourceID, 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid EKS pod resource ID format, expected vpcID/podIP")
		}
		vpcID, podIP := parts[0], parts[1]
		data, err := client.GetEKSPodByIP(ctx, podIP, vpcID)
		if err != nil {
			return nil, err
		}
		return components.NewEKSPod(data, r.accountID), nil

	case resourceTypeAPIGatewayREST:
		data, err := client.GetAPIGatewayREST(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewAPIGateway(data, r.accountID), nil

	case resourceTypeAPIGatewayHTTP:
		data, err := client.GetAPIGatewayHTTP(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewAPIGateway(data, r.accountID), nil

	case resourceTypeVPCEndpoint:
		data, err := client.GetVPCEndpoint(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewVPCEndpoint(data, r.accountID), nil

	case resourceTypeNetworkInterface:
		return components.NewNetworkInterface(r.resourceID, r.accountID), nil

	case resourceTypeDirectConnectOnPrem:
		parts := splitResourceID(r.resourceID, 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid DirectConnect on-prem resource ID format, expected dxgwID/sourceIP")
		}
		dxgwID, sourceIP := parts[0], parts[1]
		data := &domain.DirectConnectOnPremData{
			DXGWID:   dxgwID,
			SourceIP: sourceIP,
		}
		return components.NewDirectConnectOnPrem(data, r.accountID), nil

	case resourceTypeGWLBEndpoint:
		data, err := client.GetVPCEndpoint(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewGWLBEndpoint(data, r.accountID), nil

	case resourceTypeInternetGateway:
		data, err := client.GetInternetGateway(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewInternetGateway(data, r.accountID), nil

	case resourceTypeNATGateway:
		data, err := client.GetNATGateway(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewNATGateway(data, r.accountID), nil

	case resourceTypeDirectConnectGateway:
		data, err := client.GetDirectConnectGateway(ctx, r.resourceID)
		if err != nil {
			return nil, err
		}
		return components.NewDirectConnectGateway(data, r.accountID), nil

	case resourceTypeCarrierGateway:
		return components.NewCarrierGateway(r.resourceID, r.accountID), nil

	case resourceTypeLocalGateway:
		return components.NewLocalGateway(r.resourceID, r.accountID), nil

	default:
		return nil, fmt.Errorf("unsupported resource type")
	}
}

func splitResourceID(id string, n int) []string {
	return strings.SplitN(id, "/", n)
}
