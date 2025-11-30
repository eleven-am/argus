package components

import (
	"errors"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

func TestEC2Instance_GetID(t *testing.T) {
	ec2 := NewEC2Instance(&domain.EC2InstanceData{ID: "i-12345"}, "111111111111")
	if ec2.GetID() != "111111111111:i-12345" {
		t.Errorf("expected 111111111111:i-12345, got %s", ec2.GetID())
	}
}

func TestEC2Instance_GetAccountID(t *testing.T) {
	ec2 := NewEC2Instance(&domain.EC2InstanceData{ID: "i-12345"}, "111111111111")
	if ec2.GetAccountID() != "111111111111" {
		t.Errorf("expected 111111111111, got %s", ec2.GetAccountID())
	}
}

func TestEC2Instance_GetRoutingTarget(t *testing.T) {
	ec2 := NewEC2Instance(&domain.EC2InstanceData{
		ID:        "i-12345",
		PrivateIP: "10.0.1.50",
	}, "111111111111")

	target := ec2.GetRoutingTarget()

	if target.IP != "10.0.1.50" {
		t.Errorf("expected IP 10.0.1.50, got %s", target.IP)
	}
	if target.Port != 0 {
		t.Errorf("expected Port 0, got %d", target.Port)
	}
	if target.Protocol != "tcp" {
		t.Errorf("expected Protocol tcp, got %s", target.Protocol)
	}
}

func TestEC2Instance_GetNextHops(t *testing.T) {
	client := newMockAWSClient()
	client.securityGroups["sg-123"] = &domain.SecurityGroupData{
		ID:    "sg-123",
		VPCID: "vpc-1",
		OutboundRules: []domain.SecurityGroupRule{
			{Protocol: "-1", FromPort: 0, ToPort: 0, CIDRBlocks: []string{"0.0.0.0/0"}},
		},
	}
	client.securityGroups["sg-456"] = &domain.SecurityGroupData{
		ID:    "sg-456",
		VPCID: "vpc-1",
		OutboundRules: []domain.SecurityGroupRule{
			{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRBlocks: []string{"0.0.0.0/0"}},
		},
	}
	client.subnets["subnet-1"] = &domain.SubnetData{
		ID:           "subnet-1",
		VPCID:        "vpc-1",
		CIDRBlock:    "10.0.1.0/24",
		NaclID:       "nacl-1",
		RouteTableID: "rtb-1",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	ec2 := NewEC2Instance(&domain.EC2InstanceData{
		ID:             "i-12345",
		PrivateIP:      "10.0.1.50",
		SecurityGroups: []string{"sg-123", "sg-456"},
		SubnetID:       "subnet-1",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	hops, err := ec2.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop (chained SG -> SG -> Subnet), got %d", len(hops))
	}

	sg1, ok := hops[0].(*SecurityGroup)
	if !ok {
		t.Fatalf("expected SecurityGroup, got %T", hops[0])
	}

	sg2, ok := sg1.next.(*SecurityGroup)
	if !ok {
		t.Fatalf("expected second SecurityGroup, got %T", sg1.next)
	}

	if _, ok := sg2.next.(*Subnet); !ok {
		t.Errorf("expected Subnet as final component, got %T", sg2.next)
	}
}

func TestEC2Instance_GetNextHops_NoSecurityGroups(t *testing.T) {
	client := newMockAWSClient()
	client.subnets["subnet-1"] = &domain.SubnetData{
		ID:           "subnet-1",
		VPCID:        "vpc-1",
		CIDRBlock:    "10.0.1.0/24",
		NaclID:       "nacl-1",
		RouteTableID: "rtb-1",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	ec2 := NewEC2Instance(&domain.EC2InstanceData{
		ID:             "i-12345",
		PrivateIP:      "10.0.1.50",
		SecurityGroups: []string{},
		SubnetID:       "subnet-1",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	hops, err := ec2.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected 1 hop (subnet only), got %d", len(hops))
	}
}

func TestRDSInstance_GetID(t *testing.T) {
	rds := NewRDSInstance(&domain.RDSInstanceData{ID: "mydb"}, "111111111111")
	if rds.GetID() != "111111111111:mydb" {
		t.Errorf("expected 111111111111:mydb, got %s", rds.GetID())
	}
}

func TestRDSInstance_GetAccountID(t *testing.T) {
	rds := NewRDSInstance(&domain.RDSInstanceData{ID: "mydb"}, "111111111111")
	if rds.GetAccountID() != "111111111111" {
		t.Errorf("expected 111111111111, got %s", rds.GetAccountID())
	}
}

func TestRDSInstance_GetRoutingTarget(t *testing.T) {
	rds := NewRDSInstance(&domain.RDSInstanceData{
		ID:        "mydb",
		PrivateIP: "10.0.1.100",
		Port:      3306,
	}, "111111111111")

	target := rds.GetRoutingTarget()

	if target.IP != "10.0.1.100" {
		t.Errorf("expected IP 10.0.1.100, got %s", target.IP)
	}
	if target.Port != 3306 {
		t.Errorf("expected Port 3306, got %d", target.Port)
	}
	if target.Protocol != "tcp" {
		t.Errorf("expected Protocol tcp, got %s", target.Protocol)
	}
}

func TestRDSInstance_GetNextHops(t *testing.T) {
	client := newMockAWSClient()
	client.securityGroups["sg-rds"] = &domain.SecurityGroupData{
		ID:    "sg-rds",
		VPCID: "vpc-1",
		OutboundRules: []domain.SecurityGroupRule{
			{Protocol: "-1", FromPort: 0, ToPort: 0, CIDRBlocks: []string{"0.0.0.0/0"}},
		},
	}
	client.subnets["subnet-1"] = &domain.SubnetData{
		ID:           "subnet-1",
		VPCID:        "vpc-1",
		CIDRBlock:    "10.0.1.0/24",
		NaclID:       "nacl-1",
		RouteTableID: "rtb-1",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rds := NewRDSInstance(&domain.RDSInstanceData{
		ID:             "mydb",
		PrivateIP:      "10.0.1.100",
		Port:           3306,
		SecurityGroups: []string{"sg-rds"},
		SubnetIDs:      []string{"subnet-1", "subnet-2"},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	hops, err := rds.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected chained SG/subnet head, got %d", len(hops))
	}
}

func TestRDSInstance_GetNextHops_UsesFirstSubnet(t *testing.T) {
	client := newMockAWSClient()
	client.subnets["subnet-1"] = &domain.SubnetData{
		ID:           "subnet-1",
		VPCID:        "vpc-1",
		CIDRBlock:    "10.0.1.0/24",
		NaclID:       "nacl-1",
		RouteTableID: "rtb-1",
	}
	client.subnets["subnet-2"] = &domain.SubnetData{
		ID:           "subnet-2",
		VPCID:        "vpc-1",
		CIDRBlock:    "10.0.2.0/24",
		NaclID:       "nacl-2",
		RouteTableID: "rtb-2",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rds := NewRDSInstance(&domain.RDSInstanceData{
		ID:             "mydb",
		PrivateIP:      "10.0.1.100",
		Port:           3306,
		SecurityGroups: []string{},
		SubnetIDs:      []string{"subnet-1", "subnet-2"},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.3.100", Port: 443, Protocol: "tcp"}
	hops, err := rds.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}
	if hops[0].GetID() != "111111111111:subnet-1" {
		t.Errorf("expected first subnet, got %s", hops[0].GetID())
	}
}

func TestRDSInstance_GetNextHops_NoSubnets(t *testing.T) {
	client := newMockAWSClient()
	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rds := NewRDSInstance(&domain.RDSInstanceData{
		ID:             "mydb",
		PrivateIP:      "10.0.1.100",
		Port:           3306,
		SecurityGroups: []string{},
		SubnetIDs:      []string{},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.3.100", Port: 443, Protocol: "tcp"}
	_, err := rds.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error due to missing subnet data")
	}
}

func TestLambdaFunction_GetID(t *testing.T) {
	lambda := NewLambdaFunction(&domain.LambdaFunctionData{Name: "my-function"}, "111111111111")
	if lambda.GetID() != "111111111111:my-function" {
		t.Errorf("expected 111111111111:my-function, got %s", lambda.GetID())
	}
}

func TestLambdaFunction_GetAccountID(t *testing.T) {
	lambda := NewLambdaFunction(&domain.LambdaFunctionData{Name: "my-function"}, "111111111111")
	if lambda.GetAccountID() != "111111111111" {
		t.Errorf("expected 111111111111, got %s", lambda.GetAccountID())
	}
}

func TestLambdaFunction_GetRoutingTarget(t *testing.T) {
	lambda := NewLambdaFunction(&domain.LambdaFunctionData{
		Name:  "my-function",
		VPCID: "vpc-1",
	}, "111111111111")

	target := lambda.GetRoutingTarget()

	if target.IP != "" {
		t.Errorf("expected empty IP (dynamic ENI), got %s", target.IP)
	}
	if target.Port != 443 {
		t.Errorf("expected Port 443, got %d", target.Port)
	}
	if target.Protocol != "tcp" {
		t.Errorf("expected Protocol tcp, got %s", target.Protocol)
	}
}

func TestLambdaFunction_GetNextHops_VPCAttached(t *testing.T) {
	client := newMockAWSClient()
	client.securityGroups["sg-lambda"] = &domain.SecurityGroupData{
		ID:    "sg-lambda",
		VPCID: "vpc-1",
		OutboundRules: []domain.SecurityGroupRule{
			{Protocol: "-1", FromPort: 0, ToPort: 0, CIDRBlocks: []string{"0.0.0.0/0"}},
		},
	}
	client.subnets["subnet-1"] = &domain.SubnetData{
		ID:           "subnet-1",
		VPCID:        "vpc-1",
		CIDRBlock:    "10.0.1.0/24",
		NaclID:       "nacl-1",
		RouteTableID: "rtb-1",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	lambda := NewLambdaFunction(&domain.LambdaFunctionData{
		Name:           "my-function",
		VPCID:          "vpc-1",
		SubnetIDs:      []string{"subnet-1"},
		SecurityGroups: []string{"sg-lambda"},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	hops, err := lambda.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Errorf("expected chained SG/subnet head, got %d", len(hops))
	}
}

func TestLambdaFunction_GetNextHops_NotVPCAttached(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	lambda := NewLambdaFunction(&domain.LambdaFunctionData{
		Name:           "my-function",
		VPCID:          "",
		SubnetIDs:      []string{},
		SecurityGroups: []string{},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	hops, err := lambda.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error for non-VPC-attached Lambda")
	}
	if hops != nil {
		t.Errorf("expected nil hops, got %v", hops)
	}

	var blockingErr *domain.BlockingError
	ok := errors.As(err, &blockingErr)
	if !ok {
		t.Fatalf("expected BlockingError, got %T", err)
	}
	if blockingErr.Reason != "Lambda function is not VPC-attached" {
		t.Errorf("unexpected error reason: %s", blockingErr.Reason)
	}
}

func TestLambdaFunction_GetNextHops_UsesFirstSubnet(t *testing.T) {
	client := newMockAWSClient()
	client.subnets["subnet-1"] = &domain.SubnetData{
		ID:           "subnet-1",
		VPCID:        "vpc-1",
		CIDRBlock:    "10.0.1.0/24",
		NaclID:       "nacl-1",
		RouteTableID: "rtb-1",
	}
	client.subnets["subnet-2"] = &domain.SubnetData{
		ID:           "subnet-2",
		VPCID:        "vpc-1",
		CIDRBlock:    "10.0.2.0/24",
		NaclID:       "nacl-2",
		RouteTableID: "rtb-2",
	}

	accountCtx := newMockAccountContext()
	accountCtx.addClient("111111111111", client)
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	lambda := NewLambdaFunction(&domain.LambdaFunctionData{
		Name:           "my-function",
		VPCID:          "vpc-1",
		SubnetIDs:      []string{"subnet-1", "subnet-2"},
		SecurityGroups: []string{},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.3.100", Port: 443, Protocol: "tcp"}
	hops, err := lambda.GetNextHops(dest, analyzerCtx)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}
	if hops[0].GetID() != "111111111111:subnet-1" {
		t.Errorf("expected first subnet, got %s", hops[0].GetID())
	}
}

func TestEC2Instance_GetNextHops_ClientError(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	ec2 := NewEC2Instance(&domain.EC2InstanceData{
		ID:             "i-12345",
		PrivateIP:      "10.0.1.50",
		SecurityGroups: []string{"sg-123"},
		SubnetID:       "subnet-1",
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	_, err := ec2.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error when client not found")
	}
}

func TestRDSInstance_GetNextHops_ClientError(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	rds := NewRDSInstance(&domain.RDSInstanceData{
		ID:             "mydb",
		PrivateIP:      "10.0.1.100",
		Port:           3306,
		SecurityGroups: []string{"sg-rds"},
		SubnetIDs:      []string{"subnet-1"},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	_, err := rds.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error when client not found")
	}
}

func TestLambdaFunction_GetNextHops_ClientError(t *testing.T) {
	accountCtx := newMockAccountContext()
	analyzerCtx := newMockAnalyzerContext(accountCtx)

	lambda := NewLambdaFunction(&domain.LambdaFunctionData{
		Name:           "my-function",
		VPCID:          "vpc-1",
		SubnetIDs:      []string{"subnet-1"},
		SecurityGroups: []string{"sg-lambda"},
	}, "111111111111")

	dest := domain.RoutingTarget{IP: "10.0.2.100", Port: 443, Protocol: "tcp"}
	_, err := lambda.GetNextHops(dest, analyzerCtx)

	if err == nil {
		t.Fatal("expected error when client not found")
	}
}
