package analyzer

import (
	"context"

	"github.com/eleven-am/argus/internal/domain"
)

type analyzerContext struct {
	ctx        context.Context
	visited    map[string]bool
	accountCtx domain.AccountContext
}

func NewAnalyzerContext(ctx context.Context, accountCtx domain.AccountContext) domain.AnalyzerContext {
	return &analyzerContext{
		ctx:        ctx,
		visited:    make(map[string]bool),
		accountCtx: accountCtx,
	}
}

func (a *analyzerContext) MarkVisited(component domain.Component) {
	a.visited[component.GetID()] = true
}

func (a *analyzerContext) IsVisited(component domain.Component) bool {
	return a.visited[component.GetID()]
}

func (a *analyzerContext) GetAccountContext() domain.AccountContext {
	return a.accountCtx
}

func (a *analyzerContext) Context() context.Context {
	return a.ctx
}
