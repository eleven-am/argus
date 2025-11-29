package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type TargetGroup struct {
	data      *domain.TargetGroupData
	accountID string
}

func NewTargetGroup(data *domain.TargetGroupData, accountID string) *TargetGroup {
	return &TargetGroup{
		data:      data,
		accountID: accountID,
	}
}

func (tg *TargetGroup) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	var reachableTargets []domain.TargetData
	for _, t := range tg.data.Targets {
		if isTargetReachable(t.HealthStatus) {
			reachableTargets = append(reachableTargets, t)
		}
	}

	if len(reachableTargets) == 0 {
		return nil, &domain.BlockingError{
			ComponentID: tg.GetID(),
			Reason:      "no reachable targets in target group (all unhealthy or draining)",
		}
	}

	client, err := analyzerCtx.GetAccountContext().GetClient(tg.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()
	var components []domain.Component

	switch tg.data.TargetType {
	case "instance":
		for _, t := range reachableTargets {
			instance, err := client.GetEC2Instance(ctx, t.ID)
			if err != nil {
				return nil, err
			}
			components = append(components, NewEC2Instance(instance, tg.accountID))
		}

	case "ip":
		for _, t := range reachableTargets {
			ipTarget := &domain.IPTargetData{
				IP:   t.ID,
				Port: t.Port,
			}
			components = append(components, NewIPTarget(ipTarget, tg.accountID))
		}

	case "lambda":
		for _, t := range reachableTargets {
			fn, err := client.GetLambdaFunction(ctx, t.ID)
			if err != nil {
				return nil, err
			}
			components = append(components, NewLambdaFunction(fn, tg.accountID))
		}

	case "alb":
		for _, t := range reachableTargets {
			albData, err := client.GetALB(ctx, t.ID)
			if err != nil {
				return nil, err
			}
			components = append(components, NewALB(albData, tg.accountID))
		}

	default:
		return nil, &domain.BlockingError{
			ComponentID: tg.GetID(),
			Reason:      fmt.Sprintf("unknown target type: %s", tg.data.TargetType),
		}
	}

	return components, nil
}

func isTargetReachable(healthStatus string) bool {
	switch healthStatus {
	case "healthy":
		return true
	case "unhealthy":
		return false
	case "draining":
		return false
	case "unused":
		return false
	case "unavailable":
		return false
	default:
		return false
	}
}

func (tg *TargetGroup) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (tg *TargetGroup) GetID() string {
	return fmt.Sprintf("%s:%s", tg.accountID, tg.data.ARN)
}

func (tg *TargetGroup) GetAccountID() string {
	return tg.accountID
}

func (tg *TargetGroup) GetComponentType() string {
	return "TargetGroup"
}

func (tg *TargetGroup) GetVPCID() string {
	return tg.data.VPCID
}

func (tg *TargetGroup) GetRegion() string {
	return ""
}

func (tg *TargetGroup) GetSubnetID() string {
	return ""
}

func (tg *TargetGroup) GetAvailabilityZone() string {
	return ""
}
