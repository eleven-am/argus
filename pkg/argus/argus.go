package argus

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/eleven-am/argus/internal/analyzer"
	internalaws "github.com/eleven-am/argus/internal/aws"
)

// NewAccountContext creates an account context for cross-account AWS access.
// The roleARNPattern should contain %s as a placeholder for the account ID.
// Example: "arn:aws:iam::%s:role/ReachabilityAnalyzerRole"
func NewAccountContext(cfg aws.Config, roleARNPattern string) *AccountContext {
	return internalaws.NewAccountContext(cfg, roleARNPattern)
}

// TestReachability analyzes network connectivity between two AWS resources.
// It tests both directions (source→dest and dest→source) for bidirectional validation.
// Returns a ReachabilityResult containing path traces and any blocking components.
// Use the helper functions (EC2, RDS, Lambda, etc.) to create ResourceRef values.
func TestReachability(ctx context.Context, source, dest ResourceRef, accountCtx *AccountContext) (ReachabilityResult, error) {
	sourceComponent, err := source.resolve(ctx, accountCtx)
	if err != nil {
		return ReachabilityResult{}, fmt.Errorf("resolve source: %w", err)
	}

	destComponent, err := dest.resolve(ctx, accountCtx)
	if err != nil {
		return ReachabilityResult{}, fmt.Errorf("resolve destination: %w", err)
	}

	result := analyzer.TestReachability(ctx, sourceComponent, destComponent, accountCtx)
	return result, nil
}

// TestReachabilityAllPaths finds all possible network paths between two AWS resources.
// Unlike TestReachability which stops at the first successful path, this explores all routes.
// Useful for understanding redundant paths, identifying all blocking points, or auditing.
// Returns AllPathsResult with forward and return paths, including success/failure counts.
func TestReachabilityAllPaths(ctx context.Context, source, dest ResourceRef, accountCtx *AccountContext) (AllPathsResult, error) {
	sourceComponent, err := source.resolve(ctx, accountCtx)
	if err != nil {
		return AllPathsResult{}, fmt.Errorf("resolve source: %w", err)
	}

	destComponent, err := dest.resolve(ctx, accountCtx)
	if err != nil {
		return AllPathsResult{}, fmt.Errorf("resolve destination: %w", err)
	}

	result := analyzer.TestReachabilityAllPaths(ctx, sourceComponent, destComponent, accountCtx)
	return result, nil
}

// FlowSimulator provides traffic flow simulation with caching.
// Use NewFlowSimulator() or NewFlowSimulatorWithTTL() to create an instance.
type FlowSimulator = analyzer.FlowSimulator

// NewFlowSimulator creates a FlowSimulator with default 5-minute cache TTL.
func NewFlowSimulator() *FlowSimulator {
	return analyzer.NewFlowSimulator()
}

// NewFlowSimulatorWithTTL creates a FlowSimulator with a custom cache TTL.
func NewFlowSimulatorWithTTL(ttl time.Duration) *FlowSimulator {
	return analyzer.NewFlowSimulatorWithTTL(ttl)
}
