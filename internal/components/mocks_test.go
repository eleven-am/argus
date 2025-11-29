package components

import (
	"context"
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type mockAWSClient struct {
	securityGroups      map[string]*domain.SecurityGroupData
	subnets             map[string]*domain.SubnetData
	nacls               map[string]*domain.NACLData
	routeTables         map[string]*domain.RouteTableData
	vpcs                map[string]*domain.VPCData
	igws                map[string]*domain.InternetGatewayData
	natGateways         map[string]*domain.NATGatewayData
	vpcEndpoints        map[string]*domain.VPCEndpointData
	vpcPeerings         map[string]*domain.VPCPeeringData
	transitGWs          map[string]*domain.TransitGatewayData
	tgwAttachments      map[string]*domain.TGWAttachmentData
	ec2Instances        map[string]*domain.EC2InstanceData
	rdsInstances        map[string]*domain.RDSInstanceData
	lambdaFunctions     map[string]*domain.LambdaFunctionData
	vgws                map[string]*domain.VirtualPrivateGatewayData
	vpnConnections      map[string]*domain.VPNConnectionData
	dxGateways          map[string]*domain.DirectConnectGatewayData
	tgwPeerings         map[string]*domain.TGWPeeringAttachmentData
	enisBySG            map[string][]domain.ENIData
	networkENIs         map[string]*domain.ENIData
	prefixLists         map[string]*domain.ManagedPrefixListData
	albs                map[string]*domain.ALBData
	nlbs                map[string]*domain.NLBData
	gwlbs               map[string]*domain.GWLBData
	clbs                map[string]*domain.CLBData
	targetGroups        map[string]*domain.TargetGroupData
	eksPods             map[string]*domain.EKSPodData
	elasticacheClusters map[string]*domain.ElastiCacheClusterData
	dxgwAttachments     map[string][]domain.TGWAttachmentData
}

func newMockAWSClient() *mockAWSClient {
	return &mockAWSClient{
		securityGroups:      make(map[string]*domain.SecurityGroupData),
		subnets:             make(map[string]*domain.SubnetData),
		nacls:               make(map[string]*domain.NACLData),
		routeTables:         make(map[string]*domain.RouteTableData),
		vpcs:                make(map[string]*domain.VPCData),
		igws:                make(map[string]*domain.InternetGatewayData),
		natGateways:         make(map[string]*domain.NATGatewayData),
		vpcEndpoints:        make(map[string]*domain.VPCEndpointData),
		vpcPeerings:         make(map[string]*domain.VPCPeeringData),
		transitGWs:          make(map[string]*domain.TransitGatewayData),
		tgwAttachments:      make(map[string]*domain.TGWAttachmentData),
		ec2Instances:        make(map[string]*domain.EC2InstanceData),
		rdsInstances:        make(map[string]*domain.RDSInstanceData),
		lambdaFunctions:     make(map[string]*domain.LambdaFunctionData),
		vgws:                make(map[string]*domain.VirtualPrivateGatewayData),
		vpnConnections:      make(map[string]*domain.VPNConnectionData),
		dxGateways:          make(map[string]*domain.DirectConnectGatewayData),
		tgwPeerings:         make(map[string]*domain.TGWPeeringAttachmentData),
		enisBySG:            make(map[string][]domain.ENIData),
		networkENIs:         make(map[string]*domain.ENIData),
		prefixLists:         make(map[string]*domain.ManagedPrefixListData),
		albs:                make(map[string]*domain.ALBData),
		nlbs:                make(map[string]*domain.NLBData),
		gwlbs:               make(map[string]*domain.GWLBData),
		clbs:                make(map[string]*domain.CLBData),
		targetGroups:        make(map[string]*domain.TargetGroupData),
		eksPods:             make(map[string]*domain.EKSPodData),
		elasticacheClusters: make(map[string]*domain.ElastiCacheClusterData),
		dxgwAttachments:     make(map[string][]domain.TGWAttachmentData),
	}
}

func (m *mockAWSClient) GetSecurityGroup(ctx context.Context, sgID string) (*domain.SecurityGroupData, error) {
	if sg, ok := m.securityGroups[sgID]; ok {
		return sg, nil
	}
	return nil, fmt.Errorf("security group %s not found", sgID)
}

func (m *mockAWSClient) GetSubnet(ctx context.Context, subnetID string) (*domain.SubnetData, error) {
	if subnet, ok := m.subnets[subnetID]; ok {
		return subnet, nil
	}
	return nil, fmt.Errorf("subnet %s not found", subnetID)
}

func (m *mockAWSClient) GetNACL(ctx context.Context, naclID string) (*domain.NACLData, error) {
	if nacl, ok := m.nacls[naclID]; ok {
		return nacl, nil
	}
	return nil, fmt.Errorf("NACL %s not found", naclID)
}

func (m *mockAWSClient) GetRouteTable(ctx context.Context, rtID string) (*domain.RouteTableData, error) {
	if rt, ok := m.routeTables[rtID]; ok {
		return rt, nil
	}
	return nil, fmt.Errorf("route table %s not found", rtID)
}

func (m *mockAWSClient) GetVPC(ctx context.Context, vpcID string) (*domain.VPCData, error) {
	if vpc, ok := m.vpcs[vpcID]; ok {
		return vpc, nil
	}
	return nil, fmt.Errorf("VPC %s not found", vpcID)
}

func (m *mockAWSClient) GetInternetGateway(ctx context.Context, igwID string) (*domain.InternetGatewayData, error) {
	if igw, ok := m.igws[igwID]; ok {
		return igw, nil
	}
	return nil, fmt.Errorf("internet gateway %s not found", igwID)
}

func (m *mockAWSClient) GetNATGateway(ctx context.Context, natID string) (*domain.NATGatewayData, error) {
	if nat, ok := m.natGateways[natID]; ok {
		return nat, nil
	}
	return nil, fmt.Errorf("NAT gateway %s not found", natID)
}

func (m *mockAWSClient) GetVPCEndpoint(ctx context.Context, endpointID string) (*domain.VPCEndpointData, error) {
	if endpoint, ok := m.vpcEndpoints[endpointID]; ok {
		return endpoint, nil
	}
	return nil, fmt.Errorf("VPC endpoint %s not found", endpointID)
}

func (m *mockAWSClient) GetNetworkInterface(ctx context.Context, eniID string) (*domain.ENIData, error) {
	if eni, ok := m.networkENIs[eniID]; ok {
		return eni, nil
	}
	return nil, fmt.Errorf("network interface %s not found", eniID)
}

func (m *mockAWSClient) GetNetworkInterfaceByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.ENIData, error) {
	for _, eni := range m.networkENIs {
		if eni.PrivateIP == ip {
			return eni, nil
		}
	}
	return nil, nil
}

func (m *mockAWSClient) GetVPCPeering(ctx context.Context, peeringID string) (*domain.VPCPeeringData, error) {
	if peering, ok := m.vpcPeerings[peeringID]; ok {
		return peering, nil
	}
	return nil, fmt.Errorf("VPC peering %s not found", peeringID)
}

func (m *mockAWSClient) GetTransitGateway(ctx context.Context, tgwID string) (*domain.TransitGatewayData, error) {
	if tgw, ok := m.transitGWs[tgwID]; ok {
		return tgw, nil
	}
	return nil, fmt.Errorf("transit gateway %s not found", tgwID)
}

func (m *mockAWSClient) GetTransitGatewayAttachment(ctx context.Context, vpcID, tgwID string) (*domain.TGWAttachmentData, error) {
	key := vpcID + ":" + tgwID
	if att, ok := m.tgwAttachments[key]; ok {
		return att, nil
	}
	return nil, fmt.Errorf("TGW attachment for VPC %s and TGW %s not found", vpcID, tgwID)
}

func (m *mockAWSClient) GetTransitGatewayAttachmentByID(ctx context.Context, attachmentID string) (*domain.TGWAttachmentData, error) {
	if att, ok := m.tgwAttachments[attachmentID]; ok {
		return att, nil
	}
	return nil, fmt.Errorf("TGW attachment %s not found", attachmentID)
}

func (m *mockAWSClient) GetRouteTablesForAttachment(ctx context.Context, tgwID, attachmentID string) ([]string, []string, error) {
	return nil, nil, nil
}

func (m *mockAWSClient) GetEC2Instance(ctx context.Context, instanceID string) (*domain.EC2InstanceData, error) {
	if ec2, ok := m.ec2Instances[instanceID]; ok {
		return ec2, nil
	}
	return nil, fmt.Errorf("EC2 instance %s not found", instanceID)
}

func (m *mockAWSClient) GetEC2InstanceByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.EC2InstanceData, error) {
	for _, inst := range m.ec2Instances {
		if inst.PrivateIP == ip {
			return inst, nil
		}
	}
	return nil, nil
}

func (m *mockAWSClient) GetRDSInstanceByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.RDSInstanceData, error) {
	for _, db := range m.rdsInstances {
		if db.PrivateIP == ip {
			return db, nil
		}
	}
	return nil, nil
}

func (m *mockAWSClient) GetRDSInstance(ctx context.Context, dbInstanceID string) (*domain.RDSInstanceData, error) {
	if rds, ok := m.rdsInstances[dbInstanceID]; ok {
		return rds, nil
	}
	return nil, fmt.Errorf("RDS instance %s not found", dbInstanceID)
}

func (m *mockAWSClient) GetLambdaFunction(ctx context.Context, functionName string) (*domain.LambdaFunctionData, error) {
	if lambda, ok := m.lambdaFunctions[functionName]; ok {
		return lambda, nil
	}
	return nil, fmt.Errorf("lambda function %s not found", functionName)
}

func (m *mockAWSClient) GetLambdaFunctionByENIIP(ctx context.Context, ip, vpcID string) (*domain.LambdaFunctionData, error) {
	for _, fn := range m.lambdaFunctions {
		for _, eniIP := range fn.ENIIPs {
			if eniIP == ip {
				return fn, nil
			}
		}
	}
	return nil, nil
}

func (m *mockAWSClient) GetVirtualPrivateGateway(ctx context.Context, vgwID string) (*domain.VirtualPrivateGatewayData, error) {
	if vgw, ok := m.vgws[vgwID]; ok {
		return vgw, nil
	}
	return nil, fmt.Errorf("VGW %s not found", vgwID)
}

func (m *mockAWSClient) GetVPNConnection(ctx context.Context, vpnID string) (*domain.VPNConnectionData, error) {
	if vpn, ok := m.vpnConnections[vpnID]; ok {
		return vpn, nil
	}
	return nil, fmt.Errorf("VPN connection %s not found", vpnID)
}

func (m *mockAWSClient) GetVPNConnectionsByVGW(ctx context.Context, vgwID string) ([]*domain.VPNConnectionData, error) {
	var result []*domain.VPNConnectionData
	for _, vpn := range m.vpnConnections {
		if vpn.VGWID == vgwID {
			result = append(result, vpn)
		}
	}
	return result, nil
}

func (m *mockAWSClient) GetDirectConnectGateway(ctx context.Context, dxgwID string) (*domain.DirectConnectGatewayData, error) {
	if dxgw, ok := m.dxGateways[dxgwID]; ok {
		return dxgw, nil
	}
	return nil, fmt.Errorf("direct Connect Gateway %s not found", dxgwID)
}

func (m *mockAWSClient) GetTGWPeeringAttachment(ctx context.Context, attachmentID string) (*domain.TGWPeeringAttachmentData, error) {
	if peering, ok := m.tgwPeerings[attachmentID]; ok {
		return peering, nil
	}
	return nil, fmt.Errorf("TGW peering attachment %s not found", attachmentID)
}

func (m *mockAWSClient) GetENIsBySecurityGroup(ctx context.Context, sgID string) ([]domain.ENIData, error) {
	if enis, ok := m.enisBySG[sgID]; ok {
		return enis, nil
	}
	return []domain.ENIData{}, nil
}

func (m *mockAWSClient) GetManagedPrefixList(ctx context.Context, prefixListID string) (*domain.ManagedPrefixListData, error) {
	if pl, ok := m.prefixLists[prefixListID]; ok {
		return pl, nil
	}
	return nil, fmt.Errorf("managed prefix list %s not found", prefixListID)
}

func (m *mockAWSClient) GetALB(ctx context.Context, albARN string) (*domain.ALBData, error) {
	if alb, ok := m.albs[albARN]; ok {
		return alb, nil
	}
	return nil, fmt.Errorf("ALB %s not found", albARN)
}

func (m *mockAWSClient) GetALBByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.ALBData, error) {
	for _, alb := range m.albs {
		if alb.VPCID == vpcID {
			return alb, nil
		}
	}
	return nil, nil
}

func (m *mockAWSClient) GetNLB(ctx context.Context, nlbARN string) (*domain.NLBData, error) {
	if nlb, ok := m.nlbs[nlbARN]; ok {
		return nlb, nil
	}
	return nil, fmt.Errorf("NLB %s not found", nlbARN)
}

func (m *mockAWSClient) GetNLBByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.NLBData, error) {
	for _, nlb := range m.nlbs {
		if nlb.VPCID == vpcID {
			return nlb, nil
		}
	}
	return nil, nil
}

func (m *mockAWSClient) GetGWLB(ctx context.Context, gwlbARN string) (*domain.GWLBData, error) {
	if gwlb, ok := m.gwlbs[gwlbARN]; ok {
		return gwlb, nil
	}
	return nil, fmt.Errorf("GWLB %s not found", gwlbARN)
}

func (m *mockAWSClient) GetCLB(ctx context.Context, clbName string) (*domain.CLBData, error) {
	if clb, ok := m.clbs[clbName]; ok {
		return clb, nil
	}
	return nil, fmt.Errorf("CLB %s not found", clbName)
}

func (m *mockAWSClient) GetCLBByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.CLBData, error) {
	for _, clb := range m.clbs {
		if clb.VPCID == vpcID {
			return clb, nil
		}
	}
	return nil, nil
}

func (m *mockAWSClient) GetTargetGroup(ctx context.Context, tgARN string) (*domain.TargetGroupData, error) {
	if tg, ok := m.targetGroups[tgARN]; ok {
		return tg, nil
	}
	return nil, fmt.Errorf("target group %s not found", tgARN)
}

func (m *mockAWSClient) GetAPIGatewayREST(ctx context.Context, apiID string) (*domain.APIGatewayData, error) {
	return nil, fmt.Errorf("API Gateway REST %s not found", apiID)
}

func (m *mockAWSClient) GetAPIGatewayHTTP(ctx context.Context, apiID string) (*domain.APIGatewayData, error) {
	return nil, fmt.Errorf("API Gateway HTTP %s not found", apiID)
}

func (m *mockAWSClient) GetVPCLinkV1(ctx context.Context, vpcLinkID string) (*domain.VPCLinkData, error) {
	return nil, fmt.Errorf("VPC Link V1 %s not found", vpcLinkID)
}

func (m *mockAWSClient) GetVPCLinkV2(ctx context.Context, vpcLinkID string) (*domain.VPCLinkData, error) {
	return nil, fmt.Errorf("VPC Link V2 %s not found", vpcLinkID)
}

func (m *mockAWSClient) GetAPIGatewayByVPCEndpoint(ctx context.Context, vpceID string) (*domain.APIGatewayData, error) {
	return nil, nil
}

func (m *mockAWSClient) GetAPIGatewayByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.APIGatewayData, error) {
	return nil, nil
}

func (m *mockAWSClient) GetEKSPodByIP(ctx context.Context, ip, vpcID string) (*domain.EKSPodData, error) {
	if pod, ok := m.eksPods[ip]; ok {
		return pod, nil
	}
	return nil, nil
}

func (m *mockAWSClient) GetElastiCacheCluster(ctx context.Context, clusterID string) (*domain.ElastiCacheClusterData, error) {
	if cluster, ok := m.elasticacheClusters[clusterID]; ok {
		return cluster, nil
	}
	return nil, fmt.Errorf("ElastiCache cluster %s not found", clusterID)
}

func (m *mockAWSClient) GetElastiCacheClusterByPrivateIP(ctx context.Context, ip, vpcID string) (*domain.ElastiCacheClusterData, error) {
	for _, cluster := range m.elasticacheClusters {
		for _, node := range cluster.Nodes {
			if node.PrivateIP == ip {
				return cluster, nil
			}
		}
	}
	return nil, nil
}

func (m *mockAWSClient) GetDirectConnectGatewayAttachments(ctx context.Context, dxgwID string) ([]domain.TGWAttachmentData, error) {
	if attachments, ok := m.dxgwAttachments[dxgwID]; ok {
		return attachments, nil
	}
	return []domain.TGWAttachmentData{}, nil
}

type mockAccountContext struct {
	clients map[string]*mockAWSClient
}

func newMockAccountContext() *mockAccountContext {
	return &mockAccountContext{
		clients: make(map[string]*mockAWSClient),
	}
}

func (m *mockAccountContext) AssumeRole(accountID string) (domain.AWSCredentials, error) {
	return domain.AWSCredentials{}, nil
}

func (m *mockAccountContext) GetClient(accountID string) (domain.AWSClient, error) {
	if client, ok := m.clients[accountID]; ok {
		return client, nil
	}
	return nil, fmt.Errorf("no client for account %s", accountID)
}

func (m *mockAccountContext) addClient(accountID string, client *mockAWSClient) {
	m.clients[accountID] = client
}

type mockAnalyzerContext struct {
	ctx        context.Context
	accountCtx *mockAccountContext
	visited    map[string]bool
}

func newMockAnalyzerContext(accountCtx *mockAccountContext) *mockAnalyzerContext {
	return &mockAnalyzerContext{
		ctx:        context.Background(),
		accountCtx: accountCtx,
		visited:    make(map[string]bool),
	}
}

func (m *mockAnalyzerContext) MarkVisited(c domain.Component) {
	m.visited[c.GetID()] = true
}

func (m *mockAnalyzerContext) IsVisited(c domain.Component) bool {
	return m.visited[c.GetID()]
}

func (m *mockAnalyzerContext) GetAccountContext() domain.AccountContext {
	return m.accountCtx
}

func (m *mockAnalyzerContext) Context() context.Context {
	return m.ctx
}
