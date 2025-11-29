package analyzer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/eleven-am/argus/internal/domain"
)

type FlowSimulator struct {
	cache    map[string]*domain.FlowResult
	cacheTTL time.Duration
	mu       sync.RWMutex
}

func NewFlowSimulator() *FlowSimulator {
	return &FlowSimulator{
		cache:    make(map[string]*domain.FlowResult),
		cacheTTL: 5 * time.Minute,
	}
}

func NewFlowSimulatorWithTTL(ttl time.Duration) *FlowSimulator {
	return &FlowSimulator{
		cache:    make(map[string]*domain.FlowResult),
		cacheTTL: ttl,
	}
}

func (fs *FlowSimulator) SimulateFlow(
	ctx context.Context,
	source, destination domain.Component,
	traffic domain.TrafficSpec,
	accountCtx domain.AccountContext,
) (*domain.FlowResult, error) {
	cacheKey := fs.getCacheKey(source, destination, traffic)

	fs.mu.RLock()
	if cached, ok := fs.cache[cacheKey]; ok {
		fs.mu.RUnlock()
		return cached, nil
	}
	fs.mu.RUnlock()

	result := domain.NewFlowResult(traffic)

	analyzerCtx := NewAnalyzerContext(ctx, accountCtx)

	stepNum := 0
	currentComponents := []domain.Component{source}

	for len(currentComponents) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		current := currentComponents[0]
		currentComponents = currentComponents[1:]

		if analyzerCtx.IsVisited(current) {
			continue
		}
		analyzerCtx.MarkVisited(current)

		stepNum++
		step := domain.FlowStep{
			StepNumber:    stepNum,
			ComponentID:   current.GetID(),
			ComponentType: current.GetComponentType(),
			Action:        "traverse",
		}

		startTime := time.Now()

		if evaluator, ok := current.(domain.RuleEvaluator); ok {
			target := domain.RoutingTarget{
				IP:       traffic.DestinationIP,
				Port:     traffic.Port,
				Protocol: traffic.Protocol,
			}
			evalResult := evaluator.EvaluateWithDetails(target, "outbound")
			step.RuleChecks = evalResult.Evaluations

			if !evalResult.Allowed {
				step.Action = "blocked"
				step.Details = evalResult.Reason
				step.Latency = time.Since(startTime)
				result.AddStep(step)
				result.MarkBlocked(step, evalResult.Reason)
				fs.cacheResult(cacheKey, result)
				return result, nil
			}
		}

		destTarget := domain.RoutingTarget{
			IP:       traffic.DestinationIP,
			Port:     traffic.Port,
			Protocol: traffic.Protocol,
		}

		nextHops, err := current.GetNextHops(destTarget, analyzerCtx)
		step.Latency = time.Since(startTime)

		if err != nil {
			if blockErr, ok := err.(*domain.BlockingError); ok {
				step.Action = "blocked"
				step.Details = blockErr.Reason
				result.AddStep(step)
				result.MarkBlocked(step, blockErr.Reason)
				fs.cacheResult(cacheKey, result)
				return result, nil
			}
			return nil, err
		}

		step.Action = "forward"
		if len(nextHops) > 0 {
			step.Details = fmt.Sprintf("forwarding to %d next hop(s)", len(nextHops))
		} else {
			step.Details = "terminal component"
		}

		result.AddStep(step)

		for _, hop := range nextHops {
			if hop.GetID() == destination.GetID() {
				finalStep := domain.FlowStep{
					StepNumber:    stepNum + 1,
					ComponentID:   hop.GetID(),
					ComponentType: hop.GetComponentType(),
					Action:        "destination_reached",
					Details:       "traffic delivered to destination",
				}
				result.AddStep(finalStep)
				result.MarkSuccess()
				fs.cacheResult(cacheKey, result)
				return result, nil
			}
			currentComponents = append(currentComponents, hop)
		}

		if len(nextHops) == 0 {
			result.MarkSuccess()
			fs.cacheResult(cacheKey, result)
			return result, nil
		}
	}

	result.MarkBlocked(domain.FlowStep{
		StepNumber: stepNum + 1,
		Action:     "no_path",
		Details:    "no route to destination",
	}, "no route to destination")

	fs.cacheResult(cacheKey, result)
	return result, nil
}

func (fs *FlowSimulator) SimulateBidirectional(
	ctx context.Context,
	source, destination domain.Component,
	traffic domain.TrafficSpec,
	accountCtx domain.AccountContext,
) (forward, reverse *domain.FlowResult, err error) {
	forward, err = fs.SimulateFlow(ctx, source, destination, traffic, accountCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("forward simulation failed: %w", err)
	}

	reverseTraffic := domain.TrafficSpec{
		SourceIP:      traffic.DestinationIP,
		DestinationIP: traffic.SourceIP,
		Port:          traffic.Port,
		Protocol:      traffic.Protocol,
	}

	reverse, err = fs.SimulateFlow(ctx, destination, source, reverseTraffic, accountCtx)
	if err != nil {
		return forward, nil, fmt.Errorf("reverse simulation failed: %w", err)
	}

	return forward, reverse, nil
}

func (fs *FlowSimulator) ClearCache() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.cache = make(map[string]*domain.FlowResult)
}

func (fs *FlowSimulator) getCacheKey(source, dest domain.Component, traffic domain.TrafficSpec) string {
	return fmt.Sprintf("%s->%s:%s:%d:%s",
		source.GetID(),
		dest.GetID(),
		traffic.DestinationIP,
		traffic.Port,
		traffic.Protocol,
	)
}

func (fs *FlowSimulator) cacheResult(key string, result *domain.FlowResult) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.cache[key] = result

	go func() {
		time.Sleep(fs.cacheTTL)
		fs.mu.Lock()
		defer fs.mu.Unlock()
		delete(fs.cache, key)
	}()
}
