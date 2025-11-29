package analyzer

import (
	"context"
	"errors"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

type testComponent struct {
	id        string
	accountID string
	nextHops  []domain.Component
	nextErr   error
	target    domain.RoutingTarget
}

func (t *testComponent) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	return t.nextHops, t.nextErr
}

func (t *testComponent) GetRoutingTarget() domain.RoutingTarget {
	return t.target
}

func (t *testComponent) GetID() string {
	return t.id
}

func (t *testComponent) GetAccountID() string {
	return t.accountID
}

func (t *testComponent) GetComponentType() string {
	return "TestComponent"
}

type testAccountContext struct{}

func (t *testAccountContext) AssumeRole(accountID string) (domain.AWSCredentials, error) {
	return domain.AWSCredentials{}, nil
}

func (t *testAccountContext) GetClient(accountID string) (domain.AWSClient, error) {
	return nil, nil
}

func TestIsDestinationReached_Found(t *testing.T) {
	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	hops := []domain.Component{
		&testComponent{id: "sg-1", target: domain.RoutingTarget{}},
		&testComponent{id: "dest", target: domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}},
	}

	if !IsDestinationReached(hops, dest, "dest") {
		t.Error("expected destination to be reached")
	}
}

func TestIsDestinationReached_NotFound(t *testing.T) {
	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	hops := []domain.Component{
		&testComponent{id: "sg-1", target: domain.RoutingTarget{}},
		&testComponent{id: "subnet-1", target: domain.RoutingTarget{}},
	}

	if IsDestinationReached(hops, dest, "dest") {
		t.Error("expected destination NOT to be reached")
	}
}

func TestIsDestinationReached_EmptyHops(t *testing.T) {
	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}
	var hops []domain.Component

	if IsDestinationReached(hops, dest, "dest") {
		t.Error("expected destination NOT to be reached with empty hops")
	}
}

func TestTraversePath_Success(t *testing.T) {
	destComponent := &testComponent{
		id:        "dest",
		accountID: "acc-1",
		target:    domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"},
	}

	sourceComponent := &testComponent{
		id:        "source",
		accountID: "acc-1",
		nextHops:  []domain.Component{destComponent},
	}

	accountCtx := &testAccountContext{}
	analyzerCtx := NewAnalyzerContext(context.Background(), accountCtx)
	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}

	result := TraversePath(sourceComponent, dest, "dest", analyzerCtx, nil)

	if result.IsBlocked() {
		t.Errorf("expected success, got blocked: %s", result.GetBlockingReason())
	}
}

func TestTraversePath_Blocked(t *testing.T) {
	blockErr := errors.New("no outbound rule allows traffic")

	sourceComponent := &testComponent{
		id:        "source",
		accountID: "acc-1",
		nextErr:   blockErr,
	}

	accountCtx := &testAccountContext{}
	analyzerCtx := NewAnalyzerContext(context.Background(), accountCtx)
	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}

	result := TraversePath(sourceComponent, dest, "dest", analyzerCtx, nil)

	if !result.IsBlocked() {
		t.Error("expected blocked result")
	}
}

func TestTraversePath_NoRouteToDestination(t *testing.T) {
	sourceComponent := &testComponent{
		id:        "source",
		accountID: "acc-1",
		nextHops:  []domain.Component{},
	}

	accountCtx := &testAccountContext{}
	analyzerCtx := NewAnalyzerContext(context.Background(), accountCtx)
	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}

	result := TraversePath(sourceComponent, dest, "dest", analyzerCtx, nil)

	if !result.IsBlocked() {
		t.Error("expected blocked result for no route")
	}
	if result.GetBlockingReason() == "" {
		t.Error("expected blocking reason")
	}
}

func TestTraversePath_LoopDetection(t *testing.T) {
	comp1 := &testComponent{id: "comp-1", accountID: "acc-1"}
	comp2 := &testComponent{id: "comp-2", accountID: "acc-1"}

	comp1.nextHops = []domain.Component{comp2}
	comp2.nextHops = []domain.Component{comp1}

	accountCtx := &testAccountContext{}
	analyzerCtx := NewAnalyzerContext(context.Background(), accountCtx)
	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}

	result := TraversePath(comp1, dest, "dest", analyzerCtx, nil)

	if !result.IsBlocked() {
		t.Error("expected blocked result due to loop detection leading to no route")
	}
}

func TestTraversePath_MultiHopSuccess(t *testing.T) {
	destComponent := &testComponent{
		id:        "dest",
		accountID: "acc-1",
		target:    domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"},
	}

	hop2 := &testComponent{
		id:        "hop-2",
		accountID: "acc-1",
		nextHops:  []domain.Component{destComponent},
	}

	hop1 := &testComponent{
		id:        "hop-1",
		accountID: "acc-1",
		nextHops:  []domain.Component{hop2},
	}

	sourceComponent := &testComponent{
		id:        "source",
		accountID: "acc-1",
		nextHops:  []domain.Component{hop1},
	}

	accountCtx := &testAccountContext{}
	analyzerCtx := NewAnalyzerContext(context.Background(), accountCtx)
	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}

	result := TraversePath(sourceComponent, dest, "dest", analyzerCtx, nil)

	if result.IsBlocked() {
		t.Errorf("expected success for multi-hop path, got: %s", result.GetBlockingReason())
	}
}

func TestTraversePath_BlockedMidPath(t *testing.T) {
	blockErr := errors.New("NACL denies traffic")

	hop2 := &testComponent{
		id:        "hop-2",
		accountID: "acc-1",
		nextErr:   blockErr,
	}

	hop1 := &testComponent{
		id:        "hop-1",
		accountID: "acc-1",
		nextHops:  []domain.Component{hop2},
	}

	sourceComponent := &testComponent{
		id:        "source",
		accountID: "acc-1",
		nextHops:  []domain.Component{hop1},
	}

	accountCtx := &testAccountContext{}
	analyzerCtx := NewAnalyzerContext(context.Background(), accountCtx)
	dest := domain.RoutingTarget{IP: "10.0.1.100", Port: 443, Protocol: "tcp"}

	result := TraversePath(sourceComponent, dest, "dest", analyzerCtx, nil)

	if !result.IsBlocked() {
		t.Error("expected blocked result")
	}
}

func TestTestReachability_BidirectionalSuccess(t *testing.T) {
	sourceTarget := domain.RoutingTarget{IP: "10.0.1.50", Port: 0, Protocol: "tcp"}
	destTarget := domain.RoutingTarget{IP: "10.0.1.100", Port: 3306, Protocol: "tcp"}

	destComponent := &testComponent{
		id:        "dest",
		accountID: "acc-1",
		target:    destTarget,
	}

	sourceComponent := &testComponent{
		id:        "source",
		accountID: "acc-1",
		target:    sourceTarget,
	}

	sourceComponent.nextHops = []domain.Component{destComponent}
	destComponent.nextHops = []domain.Component{sourceComponent}

	accountCtx := &testAccountContext{}

	result := TestReachability(context.Background(), sourceComponent, destComponent, accountCtx)

	if !result.OverallSuccess {
		t.Error("expected bidirectional success")
	}
	if result.SourceToDestination.IsBlocked() {
		t.Errorf("source to dest should succeed: %s", result.SourceToDestination.GetBlockingReason())
	}
	if result.DestinationToSource.IsBlocked() {
		t.Errorf("dest to source should succeed: %s", result.DestinationToSource.GetBlockingReason())
	}
}

func TestTestReachability_OneWayBlocked(t *testing.T) {
	sourceTarget := domain.RoutingTarget{IP: "10.0.1.50", Port: 0, Protocol: "tcp"}
	destTarget := domain.RoutingTarget{IP: "10.0.1.100", Port: 3306, Protocol: "tcp"}

	destComponent := &testComponent{
		id:        "dest",
		accountID: "acc-1",
		target:    destTarget,
		nextErr:   errors.New("no outbound rule allows traffic"),
	}

	sourceComponent := &testComponent{
		id:        "source",
		accountID: "acc-1",
		target:    sourceTarget,
		nextHops:  []domain.Component{destComponent},
	}

	accountCtx := &testAccountContext{}

	result := TestReachability(context.Background(), sourceComponent, destComponent, accountCtx)

	if result.OverallSuccess {
		t.Error("expected overall failure when one direction is blocked")
	}
	if result.SourceToDestination.IsBlocked() {
		t.Error("source to dest should succeed")
	}
	if !result.DestinationToSource.IsBlocked() {
		t.Error("dest to source should be blocked")
	}
}

func TestTestReachability_BothDirectionsBlocked(t *testing.T) {
	sourceTarget := domain.RoutingTarget{IP: "10.0.1.50", Port: 0, Protocol: "tcp"}
	destTarget := domain.RoutingTarget{IP: "10.0.1.100", Port: 3306, Protocol: "tcp"}

	destComponent := &testComponent{
		id:        "dest",
		accountID: "acc-1",
		target:    destTarget,
		nextErr:   errors.New("blocked"),
	}

	sourceComponent := &testComponent{
		id:        "source",
		accountID: "acc-1",
		target:    sourceTarget,
		nextErr:   errors.New("blocked"),
	}

	accountCtx := &testAccountContext{}

	result := TestReachability(context.Background(), sourceComponent, destComponent, accountCtx)

	if result.OverallSuccess {
		t.Error("expected overall failure when both directions blocked")
	}
	if !result.SourceToDestination.IsBlocked() {
		t.Error("source to dest should be blocked")
	}
	if !result.DestinationToSource.IsBlocked() {
		t.Error("dest to source should be blocked")
	}
}

func TestFilterVisited(t *testing.T) {
	accountCtx := &testAccountContext{}
	analyzerCtx := NewAnalyzerContext(context.Background(), accountCtx)

	comp1 := &testComponent{id: "comp-1", accountID: "acc-1"}
	comp2 := &testComponent{id: "comp-2", accountID: "acc-1"}
	comp3 := &testComponent{id: "comp-3", accountID: "acc-1"}

	analyzerCtx.MarkVisited(comp1)
	analyzerCtx.MarkVisited(comp3)

	hops := []domain.Component{comp1, comp2, comp3}
	filtered := filterVisited(hops, analyzerCtx)

	if len(filtered) != 1 {
		t.Errorf("expected 1 unvisited component, got %d", len(filtered))
	}
	if filtered[0].GetID() != "comp-2" {
		t.Errorf("expected comp-2, got %s", filtered[0].GetID())
	}
}
