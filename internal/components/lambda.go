package components

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/eleven-am/argus/internal/domain"
)

type LambdaFunction struct {
	data      *domain.LambdaFunctionData
	accountID string
}

func NewLambdaFunction(data *domain.LambdaFunctionData, accountID string) *LambdaFunction {
	return &LambdaFunction{
		data:      data,
		accountID: accountID,
	}
}

func (l *LambdaFunction) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	if l.data.VPCID == "" {
		return nil, &domain.BlockingError{
			ComponentID: l.GetID(),
			Reason:      "Lambda function is not VPC-attached",
		}
	}

	client, err := analyzerCtx.GetAccountContext().GetClient(l.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	var components []domain.Component

	for _, sgID := range l.data.SecurityGroups {
		sgData, err := client.GetSecurityGroup(ctx, sgID)
		if err != nil {
			return nil, err
		}
		components = append(components, NewSecurityGroup(sgData, l.accountID))
	}

	if len(l.data.SubnetIDs) > 0 {
		subnetData, err := client.GetSubnet(ctx, l.data.SubnetIDs[0])
		if err != nil {
			return nil, err
		}
		components = append(components, NewSubnet(subnetData, l.accountID))
	}

	return components, nil
}

func (l *LambdaFunction) GetRoutingTarget() domain.RoutingTarget {
	ip := ""
	if len(l.data.SubnetCIDRs) > 0 {
		ip = getRepresentativeIP(l.data.SubnetCIDRs[0])
	}
	return domain.RoutingTarget{
		IP:       ip,
		Port:     443,
		Protocol: "tcp",
	}
}

func getRepresentativeIP(cidr string) string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return ""
	}
	ipParts := strings.Split(parts[0], ".")
	if len(ipParts) != 4 {
		return ""
	}
	lastOctet := 10
	if val, err := strconv.Atoi(ipParts[3]); err == nil {
		lastOctet = val + 10
		if lastOctet > 250 {
			lastOctet = 10
		}
	}
	return fmt.Sprintf("%s.%s.%s.%d", ipParts[0], ipParts[1], ipParts[2], lastOctet)
}

func (l *LambdaFunction) GetID() string {
	return fmt.Sprintf("%s:%s", l.accountID, l.data.Name)
}

func (l *LambdaFunction) GetAccountID() string {
	return l.accountID
}

func (l *LambdaFunction) GetComponentType() string {
	return "LambdaFunction"
}

func (l *LambdaFunction) GetVPCID() string {
	return l.data.VPCID
}

func (l *LambdaFunction) GetRegion() string {
	return ""
}

func (l *LambdaFunction) GetSubnetID() string {
	if len(l.data.SubnetIDs) > 0 {
		return l.data.SubnetIDs[0]
	}
	return ""
}

func (l *LambdaFunction) GetAvailabilityZone() string {
	return ""
}
