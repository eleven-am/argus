# Argus

Argus tests network reachability between AWS resources. It simulates traffic paths through VPC components (security groups, NACLs, route tables, gateways) and reports whether traffic can flow between a source and destination.

## How it works

Given two resources, Argus:

1. Resolves each resource to its network configuration (IPs, subnets, security groups, etc.)
2. Traverses the path from source to destination, checking each component
3. Traverses the return path from destination to source
4. Reports success only if both directions allow traffic

The traversal checks:
- Security group rules (inbound/outbound)
- Network ACL rules
- Route table entries
- Gateway configurations (IGW, NAT, Transit Gateway, etc.)
- VPC peering connections
- Cross-account routing

## Installation

```bash
go get github.com/eleven-am/argus
```

## Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/eleven-am/argus/pkg/argus"
)

func main() {
    ctx := context.Background()

    // Load AWS config
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        log.Fatal(err)
    }

    // Create account context with role pattern for cross-account access
    // The %s is replaced with the account ID when assuming roles
    accountCtx := argus.NewAccountContext(cfg, "arn:aws:iam::%s:role/ArgusRole")

    // Define source and destination
    source := argus.EC2("111111111111", "i-0abc123def456")
    dest := argus.RDS("111111111111", "my-database")

    // Test reachability
    result, err := argus.TestReachability(ctx, source, dest, accountCtx)
    if err != nil {
        log.Fatal(err)
    }

    if result.OverallSuccess {
        fmt.Println("Traffic can flow in both directions")
    } else {
        if result.SourceToDestination.IsBlocked() {
            fmt.Printf("Blocked forward: %s\n", result.SourceToDestination.GetBlockingReason())
        }
        if result.DestinationToSource.IsBlocked() {
            fmt.Printf("Blocked return: %s\n", result.DestinationToSource.GetBlockingReason())
        }
    }
}
```

## Supported Resources

### Compute & Database
- `EC2(accountID, instanceID)` - EC2 instances
- `RDS(accountID, dbIdentifier)` - RDS databases
- `Lambda(accountID, functionName)` - Lambda functions
- `ElastiCache(accountID, clusterID)` - ElastiCache clusters
- `EKSPod(accountID, vpcID, podIP)` - EKS pods by IP

### Load Balancers
- `ALB(accountID, albARN)` - Application Load Balancer
- `NLB(accountID, nlbARN)` - Network Load Balancer
- `CLB(accountID, clbName)` - Classic Load Balancer
- `GWLB(accountID, gwlbARN)` - Gateway Load Balancer

### Gateways
- `InternetGateway(accountID, igwID)` - Internet Gateway
- `NATGateway(accountID, natID)` - NAT Gateway
- `DirectConnectGateway(accountID, dxgwID)` - Direct Connect Gateway
- `CarrierGateway(accountID, cgwID)` - Carrier Gateway (Wavelength)
- `LocalGateway(accountID, lgwID)` - Local Gateway (Outposts)

### Endpoints & Interfaces
- `VPCEndpoint(accountID, vpceID)` - VPC Endpoint
- `GWLBEndpoint(accountID, vpceID)` - Gateway Load Balancer Endpoint
- `NetworkInterface(accountID, eniID)` - Elastic Network Interface
- `APIGatewayREST(accountID, apiID)` - REST API Gateway
- `APIGatewayHTTP(accountID, apiID)` - HTTP API Gateway

### External
- `ExternalIP(ip, port)` - External IP address (e.g., internet destinations)
- `OnPremDirectConnect(accountID, dxgwID, sourceIP)` - On-premises via Direct Connect

## Path Tracing

Results include path traces showing each hop:

```go
if result.ForwardPath != nil {
    for _, hop := range result.ForwardPath.Hops {
        fmt.Printf("%s (%s): %s\n",
            hop.ComponentID,
            hop.ComponentType,
            hop.Action)
    }
}
```

Actions indicate what happened at each hop:
- `Allowed` - Traffic permitted (e.g., security group rule matched)
- `Blocked` - Traffic denied
- `Routed` - Route table directed traffic
- `Forwarded` - Component forwarded traffic (e.g., NAT Gateway)
- `Entered` - Traffic entered a component
- `Resolved` - DNS or endpoint resolved
- `Terminal` - Final destination reached

## Cross-Account Access

Argus assumes roles to access resources in different accounts. The role ARN pattern uses `%s` as a placeholder for the account ID:

```go
accountCtx := argus.NewAccountContext(cfg, "arn:aws:iam::%s:role/ArgusRole")
```

When testing reachability for resources in account `111111111111`, Argus assumes `arn:aws:iam::111111111111:role/ArgusRole`.

The role needs read-only permissions to describe VPC components, EC2, RDS, Lambda, load balancers, and related resources. See [examples/iam-policy.json](examples/iam-policy.json) for a complete IAM policy.

For cross-account access, each target account needs a role with this policy and a trust relationship allowing assumption from the account running Argus. See [examples/trust-policy.json](examples/trust-policy.json) for a trust policy template.

## Limitations

- Analyzes configuration only, does not send actual network traffic
- Does not account for host-level firewalls or OS configurations
- Transit Gateway route table analysis requires appropriate permissions
- Some edge cases in complex multi-account setups may not be fully covered
