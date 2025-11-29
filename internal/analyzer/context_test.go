package analyzer

import (
	"context"
	"testing"

	"github.com/eleven-am/argus/internal/domain"
)

type mockComponent struct {
	id        string
	accountID string
}

func (m *mockComponent) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	return nil, nil
}

func (m *mockComponent) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (m *mockComponent) GetID() string {
	return m.id
}

func (m *mockComponent) GetAccountID() string {
	return m.accountID
}

func (m *mockComponent) GetComponentType() string {
	return "MockComponent"
}

type mockAccountContext struct{}

func (m *mockAccountContext) AssumeRole(accountID string) (domain.AWSCredentials, error) {
	return domain.AWSCredentials{}, nil
}

func (m *mockAccountContext) GetClient(accountID string) (domain.AWSClient, error) {
	return nil, nil
}

func TestNewAnalyzerContext(t *testing.T) {
	accountCtx := &mockAccountContext{}
	ctx := NewAnalyzerContext(context.Background(), accountCtx)

	if ctx == nil {
		t.Fatal("expected non-nil AnalyzerContext")
	}
}

func TestAnalyzerContext_MarkVisited(t *testing.T) {
	accountCtx := &mockAccountContext{}
	ctx := NewAnalyzerContext(context.Background(), accountCtx)

	component := &mockComponent{id: "test-123", accountID: "acc-1"}

	if ctx.IsVisited(component) {
		t.Error("component should not be visited initially")
	}

	ctx.MarkVisited(component)

	if !ctx.IsVisited(component) {
		t.Error("component should be visited after MarkVisited")
	}
}

func TestAnalyzerContext_IsVisited_MultipleComponents(t *testing.T) {
	accountCtx := &mockAccountContext{}
	ctx := NewAnalyzerContext(context.Background(), accountCtx)

	comp1 := &mockComponent{id: "comp-1", accountID: "acc-1"}
	comp2 := &mockComponent{id: "comp-2", accountID: "acc-1"}
	comp3 := &mockComponent{id: "comp-3", accountID: "acc-2"}

	ctx.MarkVisited(comp1)
	ctx.MarkVisited(comp3)

	if !ctx.IsVisited(comp1) {
		t.Error("comp1 should be visited")
	}
	if ctx.IsVisited(comp2) {
		t.Error("comp2 should not be visited")
	}
	if !ctx.IsVisited(comp3) {
		t.Error("comp3 should be visited")
	}
}

func TestAnalyzerContext_IsVisited_SameIDDifferentObjects(t *testing.T) {
	accountCtx := &mockAccountContext{}
	ctx := NewAnalyzerContext(context.Background(), accountCtx)

	comp1 := &mockComponent{id: "same-id", accountID: "acc-1"}
	comp2 := &mockComponent{id: "same-id", accountID: "acc-1"}

	ctx.MarkVisited(comp1)

	if !ctx.IsVisited(comp2) {
		t.Error("components with same ID should be considered visited")
	}
}

func TestAnalyzerContext_GetAccountContext(t *testing.T) {
	accountCtx := &mockAccountContext{}
	ctx := NewAnalyzerContext(context.Background(), accountCtx)

	result := ctx.GetAccountContext()

	if result != accountCtx {
		t.Error("GetAccountContext should return the same AccountContext")
	}
}
