package resolver

import (
	"context"

	"github.com/eleven-am/argus/internal/components"
	"github.com/eleven-am/argus/internal/domain"
)

type SimpleResolver struct {
	accountCtx domain.AccountContext
	cacheIP    map[string]domain.Component
	cacheID    map[string]domain.Component
}

func NewSimpleResolver(accountCtx domain.AccountContext) *SimpleResolver {
	return &SimpleResolver{
		accountCtx: accountCtx,
		cacheIP:    make(map[string]domain.Component),
		cacheID:    make(map[string]domain.Component),
	}
}

func (r *SimpleResolver) ResolveByIP(ctx context.Context, accountID, vpcID, ip string) (domain.Component, error) {
	if ip == "" {
		return nil, nil
	}
	if comp, ok := r.cacheIP[ip]; ok {
		return comp, nil
	}
	client, err := r.accountCtx.GetClient(accountID)
	if err != nil {
		return nil, err
	}

	if eni, err := client.GetNetworkInterfaceByPrivateIP(ctx, ip, vpcID); err == nil && eni != nil {
		comp := components.NewNetworkInterface(eni.ID, accountID)
		r.cacheIP[ip] = comp
		return comp, nil
	}

	if inst, err := client.GetEC2InstanceByPrivateIP(ctx, ip, vpcID); err == nil && inst != nil {
		comp := components.NewEC2Instance(inst, accountID)
		r.cacheIP[ip] = comp
		return comp, nil
	}

	if rds, err := client.GetRDSInstanceByPrivateIP(ctx, ip, vpcID); err == nil && rds != nil {
		comp := components.NewRDSInstance(rds, accountID)
		r.cacheIP[ip] = comp
		return comp, nil
	}

	if lambda, err := client.GetLambdaFunctionByENIIP(ctx, ip, vpcID); err == nil && lambda != nil {
		comp := components.NewLambdaFunction(lambda, accountID)
		r.cacheIP[ip] = comp
		return comp, nil
	}

	if alb, err := client.GetALBByPrivateIP(ctx, ip, vpcID); err == nil && alb != nil {
		comp := components.NewALB(alb, accountID)
		r.cacheIP[ip] = comp
		return comp, nil
	}

	if nlb, err := client.GetNLBByPrivateIP(ctx, ip, vpcID); err == nil && nlb != nil {
		comp := components.NewNLB(nlb, accountID)
		r.cacheIP[ip] = comp
		return comp, nil
	}

	if clb, err := client.GetCLBByPrivateIP(ctx, ip, vpcID); err == nil && clb != nil {
		comp := components.NewCLB(clb, accountID)
		r.cacheIP[ip] = comp
		return comp, nil
	}

	if apigw, err := client.GetAPIGatewayByPrivateIP(ctx, ip, vpcID); err == nil && apigw != nil {
		comp := components.NewAPIGateway(apigw, accountID)
		r.cacheIP[ip] = comp
		return comp, nil
	}

	if eksPod, err := client.GetEKSPodByIP(ctx, ip, vpcID); err == nil && eksPod != nil {
		comp := components.NewEKSPod(eksPod, accountID)
		r.cacheIP[ip] = comp
		return comp, nil
	}

	if elasticache, err := client.GetElastiCacheClusterByPrivateIP(ctx, ip, vpcID); err == nil && elasticache != nil {
		comp := components.NewElastiCacheCluster(elasticache, accountID)
		r.cacheIP[ip] = comp
		return comp, nil
	}

	return nil, nil
}

func (r *SimpleResolver) ResolveByID(ctx context.Context, id string) (domain.Component, error) {
	if id == "" {
		return nil, nil
	}
	if comp, ok := r.cacheID[id]; ok {
		return comp, nil
	}
	return nil, nil
}
