package domain

import (
	"context"
	"time"
)

type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

type AccountContext interface {
	AssumeRole(accountID string) (AWSCredentials, error)
	GetClient(accountID string) (AWSClient, error)
}

type AWSClient interface {
	GetSecurityGroup(ctx context.Context, sgID string) (*SecurityGroupData, error)
	GetSubnet(ctx context.Context, subnetID string) (*SubnetData, error)
	GetNACL(ctx context.Context, naclID string) (*NACLData, error)
	GetRouteTable(ctx context.Context, rtID string) (*RouteTableData, error)
	GetVPC(ctx context.Context, vpcID string) (*VPCData, error)
	GetInternetGateway(ctx context.Context, igwID string) (*InternetGatewayData, error)
	GetNATGateway(ctx context.Context, natID string) (*NATGatewayData, error)
	GetVPCEndpoint(ctx context.Context, endpointID string) (*VPCEndpointData, error)
	GetVPCPeering(ctx context.Context, peeringID string) (*VPCPeeringData, error)

	GetTransitGateway(ctx context.Context, tgwID string) (*TransitGatewayData, error)
	GetTransitGatewayAttachment(ctx context.Context, vpcID, tgwID string) (*TGWAttachmentData, error)
	GetTransitGatewayAttachmentByID(ctx context.Context, attachmentID string) (*TGWAttachmentData, error)
	GetRouteTablesForAttachment(ctx context.Context, tgwID, attachmentID string) (associated []string, propagated []string, err error)

	GetEC2Instance(ctx context.Context, instanceID string) (*EC2InstanceData, error)
	GetRDSInstance(ctx context.Context, dbInstanceID string) (*RDSInstanceData, error)
	GetLambdaFunction(ctx context.Context, functionName string) (*LambdaFunctionData, error)

	GetVirtualPrivateGateway(ctx context.Context, vgwID string) (*VirtualPrivateGatewayData, error)
	GetVPNConnection(ctx context.Context, vpnID string) (*VPNConnectionData, error)
	GetVPNConnectionsByVGW(ctx context.Context, vgwID string) ([]*VPNConnectionData, error)
	GetDirectConnectGateway(ctx context.Context, dxgwID string) (*DirectConnectGatewayData, error)
	GetTGWPeeringAttachment(ctx context.Context, attachmentID string) (*TGWPeeringAttachmentData, error)
	GetNetworkInterface(ctx context.Context, eniID string) (*ENIData, error)

	GetENIsBySecurityGroup(ctx context.Context, sgID string) ([]ENIData, error)
	GetNetworkInterfaceByPrivateIP(ctx context.Context, ip, vpcID string) (*ENIData, error)
	GetEC2InstanceByPrivateIP(ctx context.Context, ip, vpcID string) (*EC2InstanceData, error)
	GetRDSInstanceByPrivateIP(ctx context.Context, ip, vpcID string) (*RDSInstanceData, error)
	GetLambdaFunctionByENIIP(ctx context.Context, ip, vpcID string) (*LambdaFunctionData, error)
	GetManagedPrefixList(ctx context.Context, prefixListID string) (*ManagedPrefixListData, error)

	GetALB(ctx context.Context, albARN string) (*ALBData, error)
	GetNLB(ctx context.Context, nlbARN string) (*NLBData, error)
	GetGWLB(ctx context.Context, gwlbARN string) (*GWLBData, error)
	GetCLB(ctx context.Context, clbName string) (*CLBData, error)
	GetTargetGroup(ctx context.Context, tgARN string) (*TargetGroupData, error)

	GetALBByPrivateIP(ctx context.Context, ip, vpcID string) (*ALBData, error)
	GetNLBByPrivateIP(ctx context.Context, ip, vpcID string) (*NLBData, error)
	GetCLBByPrivateIP(ctx context.Context, ip, vpcID string) (*CLBData, error)

	GetAPIGatewayREST(ctx context.Context, apiID string) (*APIGatewayData, error)
	GetAPIGatewayHTTP(ctx context.Context, apiID string) (*APIGatewayData, error)
	GetVPCLinkV1(ctx context.Context, vpcLinkID string) (*VPCLinkData, error)
	GetVPCLinkV2(ctx context.Context, vpcLinkID string) (*VPCLinkData, error)
	GetAPIGatewayByVPCEndpoint(ctx context.Context, vpceID string) (*APIGatewayData, error)
	GetAPIGatewayByPrivateIP(ctx context.Context, ip, vpcID string) (*APIGatewayData, error)

	GetEKSPodByIP(ctx context.Context, ip, vpcID string) (*EKSPodData, error)

	GetElastiCacheCluster(ctx context.Context, clusterID string) (*ElastiCacheClusterData, error)
	GetElastiCacheClusterByPrivateIP(ctx context.Context, ip, vpcID string) (*ElastiCacheClusterData, error)

	GetDirectConnectGatewayAttachments(ctx context.Context, dxgwID string) ([]TGWAttachmentData, error)

	GetNetworkFirewall(ctx context.Context, firewallID string) (*NetworkFirewallData, error)
	GetNetworkFirewallByEndpoint(ctx context.Context, endpointID string) (*NetworkFirewallData, error)
}

type AnalyzerContext interface {
	MarkVisited(component Component)
	IsVisited(component Component) bool
	GetAccountContext() AccountContext
	Context() context.Context
}
