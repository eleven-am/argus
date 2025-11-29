package domain

type Component interface {
	GetNextHops(destination RoutingTarget, analyzerCtx AnalyzerContext) ([]Component, error)
	GetRoutingTarget() RoutingTarget
	GetID() string
	GetAccountID() string
	GetComponentType() string
}

type TerminalComponent interface {
	Component
	IsTerminal() bool
}

type FilterComponent interface {
	Component
	IsFilter() bool
	EvaluateOutbound(dest RoutingTarget, analyzerCtx AnalyzerContext) error
	EvaluateInbound(source RoutingTarget, analyzerCtx AnalyzerContext) error
}

type MetadataProvider interface {
	GetVPCID() string
	GetRegion() string
	GetSubnetID() string
	GetAvailabilityZone() string
}
