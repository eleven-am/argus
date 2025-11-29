package domain

type RuleEvaluation struct {
	RuleID     string
	RuleType   string
	Action     string
	Matched    bool
	Reason     string
	SourceCIDR string
	DestCIDR   string
	Protocol   string
	PortFrom   int
	PortTo     int
	Priority   int
}

type EvaluationResult struct {
	Allowed     bool
	Reason      string
	Evaluations []RuleEvaluation
}

type RuleEvaluator interface {
	EvaluateWithDetails(target RoutingTarget, direction string) EvaluationResult
}
