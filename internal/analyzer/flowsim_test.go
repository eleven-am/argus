package analyzer

import (
	"context"
	"testing"
	"time"

	"github.com/eleven-am/argus/internal/domain"
)

type flowTestComponent struct {
	id            string
	componentType string
	nextHops      []domain.Component
	blockError    *domain.BlockingError
}

func (m *flowTestComponent) GetNextHops(dest domain.RoutingTarget, ctx domain.AnalyzerContext) ([]domain.Component, error) {
	if m.blockError != nil {
		return nil, m.blockError
	}
	return m.nextHops, nil
}

func (m *flowTestComponent) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (m *flowTestComponent) GetID() string {
	return m.id
}

func (m *flowTestComponent) GetAccountID() string {
	return "123456789"
}

func (m *flowTestComponent) GetComponentType() string {
	return m.componentType
}

func (m *flowTestComponent) GetVPCID() string {
	return "vpc-123"
}

func (m *flowTestComponent) GetRegion() string {
	return "us-east-1"
}

func (m *flowTestComponent) GetSubnetID() string {
	return ""
}

func (m *flowTestComponent) GetAvailabilityZone() string {
	return ""
}

type flowTestAccountContext struct{}

func (m *flowTestAccountContext) AssumeRole(accountID string) (domain.AWSCredentials, error) {
	return domain.AWSCredentials{}, nil
}

func (m *flowTestAccountContext) GetClient(accountID string) (domain.AWSClient, error) {
	return nil, nil
}

func TestFlowSimulator_SimulateFlow_Success(t *testing.T) {
	fs := NewFlowSimulator()

	dest := &flowTestComponent{id: "dest-1", componentType: "EC2"}
	source := &flowTestComponent{
		id:            "source-1",
		componentType: "EC2",
		nextHops:      []domain.Component{dest},
	}

	traffic := domain.TrafficSpec{
		SourceIP:      "10.0.1.1",
		DestinationIP: "10.0.2.1",
		Port:          443,
		Protocol:      "tcp",
	}

	ctx := context.Background()
	accountCtx := &flowTestAccountContext{}

	result, err := fs.SimulateFlow(ctx, source, dest, traffic, accountCtx)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if len(result.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(result.Steps))
	}
}

func TestFlowSimulator_SimulateFlow_Blocked(t *testing.T) {
	fs := NewFlowSimulator()

	dest := &flowTestComponent{id: "dest-1", componentType: "EC2"}
	blocker := &flowTestComponent{
		id:            "blocker-1",
		componentType: "SecurityGroup",
		blockError:    &domain.BlockingError{ComponentID: "blocker-1", Reason: "denied by security group"},
	}
	source := &flowTestComponent{
		id:            "source-1",
		componentType: "EC2",
		nextHops:      []domain.Component{blocker},
	}

	traffic := domain.TrafficSpec{
		SourceIP:      "10.0.1.1",
		DestinationIP: "10.0.2.1",
		Port:          443,
		Protocol:      "tcp",
	}

	ctx := context.Background()
	accountCtx := &flowTestAccountContext{}

	result, err := fs.SimulateFlow(ctx, source, dest, traffic, accountCtx)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result.Success {
		t.Error("expected blocked result")
	}
	if result.BlockedAt == nil {
		t.Error("expected BlockedAt to be set")
	}
	if result.FailureReason == "" {
		t.Error("expected failure reason")
	}
}

func TestFlowSimulator_SimulateFlow_MultiHop(t *testing.T) {
	fs := NewFlowSimulator()

	dest := &flowTestComponent{id: "dest-1", componentType: "EC2"}
	hop2 := &flowTestComponent{id: "hop-2", componentType: "RouteTable", nextHops: []domain.Component{dest}}
	hop1 := &flowTestComponent{id: "hop-1", componentType: "Subnet", nextHops: []domain.Component{hop2}}
	source := &flowTestComponent{id: "source-1", componentType: "EC2", nextHops: []domain.Component{hop1}}

	traffic := domain.TrafficSpec{
		SourceIP:      "10.0.1.1",
		DestinationIP: "10.0.2.1",
		Port:          443,
		Protocol:      "tcp",
	}

	ctx := context.Background()
	accountCtx := &flowTestAccountContext{}

	result, err := fs.SimulateFlow(ctx, source, dest, traffic, accountCtx)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
	if len(result.Steps) != 4 {
		t.Errorf("expected 4 steps, got %d", len(result.Steps))
	}

	path := result.GetPath()
	if len(path) != 4 {
		t.Errorf("expected path length 4, got %d", len(path))
	}
}

func TestFlowSimulator_SimulateBidirectional(t *testing.T) {
	fs := NewFlowSimulator()

	dest := &flowTestComponent{id: "dest-1", componentType: "EC2"}
	source := &flowTestComponent{id: "source-1", componentType: "EC2", nextHops: []domain.Component{dest}}
	dest.nextHops = []domain.Component{source}

	traffic := domain.TrafficSpec{
		SourceIP:      "10.0.1.1",
		DestinationIP: "10.0.2.1",
		Port:          443,
		Protocol:      "tcp",
	}

	ctx := context.Background()
	accountCtx := &flowTestAccountContext{}

	forward, reverse, err := fs.SimulateBidirectional(ctx, source, dest, traffic, accountCtx)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !forward.Success {
		t.Error("expected forward success")
	}
	if !reverse.Success {
		t.Error("expected reverse success")
	}
}

func TestFlowSimulator_CacheHit(t *testing.T) {
	fs := NewFlowSimulatorWithTTL(1 * time.Minute)

	dest := &flowTestComponent{id: "dest-1", componentType: "EC2"}
	source := &flowTestComponent{id: "source-1", componentType: "EC2", nextHops: []domain.Component{dest}}

	traffic := domain.TrafficSpec{
		SourceIP:      "10.0.1.1",
		DestinationIP: "10.0.2.1",
		Port:          443,
		Protocol:      "tcp",
	}

	ctx := context.Background()
	accountCtx := &flowTestAccountContext{}

	result1, _ := fs.SimulateFlow(ctx, source, dest, traffic, accountCtx)
	result2, _ := fs.SimulateFlow(ctx, source, dest, traffic, accountCtx)

	if result1 != result2 {
		t.Error("expected cached result to be returned")
	}
}

func TestFlowSimulator_ClearCache(t *testing.T) {
	fs := NewFlowSimulatorWithTTL(1 * time.Minute)

	dest := &flowTestComponent{id: "dest-1", componentType: "EC2"}
	source := &flowTestComponent{id: "source-1", componentType: "EC2", nextHops: []domain.Component{dest}}

	traffic := domain.TrafficSpec{
		SourceIP:      "10.0.1.1",
		DestinationIP: "10.0.2.1",
		Port:          443,
		Protocol:      "tcp",
	}

	ctx := context.Background()
	accountCtx := &flowTestAccountContext{}

	result1, _ := fs.SimulateFlow(ctx, source, dest, traffic, accountCtx)

	fs.ClearCache()

	result2, _ := fs.SimulateFlow(ctx, source, dest, traffic, accountCtx)

	if result1 == result2 {
		t.Error("expected new result after cache clear")
	}
}

func TestFlowResult_Methods(t *testing.T) {
	result := domain.NewFlowResult(domain.TrafficSpec{
		SourceIP:      "10.0.1.1",
		DestinationIP: "10.0.2.1",
		Port:          443,
		Protocol:      "tcp",
	})

	step1 := domain.FlowStep{
		StepNumber:    1,
		ComponentID:   "comp-1",
		ComponentType: "EC2",
		Action:        "forward",
		Latency:       10 * time.Millisecond,
	}

	step2 := domain.FlowStep{
		StepNumber:    2,
		ComponentID:   "comp-2",
		ComponentType: "SecurityGroup",
		Action:        "forward",
		Latency:       5 * time.Millisecond,
		RuleChecks:    []domain.RuleEvaluation{{RuleID: "rule-1"}},
	}

	result.AddStep(step1)
	result.AddStep(step2)
	result.MarkSuccess()

	if !result.Success {
		t.Error("expected success")
	}
	if result.TotalLatency != 15*time.Millisecond {
		t.Errorf("expected 15ms latency, got %v", result.TotalLatency)
	}

	path := result.GetPath()
	if len(path) != 2 || path[0] != "comp-1" || path[1] != "comp-2" {
		t.Errorf("unexpected path: %v", path)
	}

	types := result.GetComponentTypes()
	if len(types) != 2 || types[0] != "EC2" || types[1] != "SecurityGroup" {
		t.Errorf("unexpected types: %v", types)
	}

	found := result.FindStepByComponent("comp-2")
	if found == nil || found.ComponentID != "comp-2" {
		t.Error("expected to find step by component")
	}

	notFound := result.FindStepByComponent("comp-999")
	if notFound != nil {
		t.Error("expected nil for non-existent component")
	}

	if !result.HasRuleEvaluations() {
		t.Error("expected HasRuleEvaluations to return true")
	}
}

func TestFlowResult_BlockedMethods(t *testing.T) {
	result := domain.NewFlowResult(domain.TrafficSpec{})

	step := domain.FlowStep{
		StepNumber:    1,
		ComponentID:   "blocker-1",
		ComponentType: "NACL",
		Action:        "blocked",
	}

	result.AddStep(step)
	result.MarkBlocked(step, "denied by NACL")

	if result.Success {
		t.Error("expected failure")
	}
	if result.GetBlockingComponent() != "blocker-1" {
		t.Errorf("expected blocker-1, got %s", result.GetBlockingComponent())
	}
	if result.FailureReason != "denied by NACL" {
		t.Errorf("expected 'denied by NACL', got %s", result.FailureReason)
	}
}
