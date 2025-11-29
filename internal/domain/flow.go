package domain

import (
	"time"
)

type TrafficSpec struct {
	SourceIP      string
	DestinationIP string
	Port          int
	Protocol      string
}

type FlowStep struct {
	StepNumber    int
	ComponentID   string
	ComponentType string
	Action        string
	Latency       time.Duration
	RuleChecks    []RuleEvaluation
	Details       string
}

type FlowResult struct {
	Success       bool
	Steps         []FlowStep
	TotalLatency  time.Duration
	BlockedAt     *FlowStep
	FailureReason string
	TrafficSpec   TrafficSpec
}

func NewFlowResult(spec TrafficSpec) *FlowResult {
	return &FlowResult{
		TrafficSpec: spec,
		Steps:       []FlowStep{},
	}
}

func (r *FlowResult) AddStep(step FlowStep) {
	r.Steps = append(r.Steps, step)
	r.TotalLatency += step.Latency
}

func (r *FlowResult) MarkBlocked(step FlowStep, reason string) {
	r.Success = false
	r.BlockedAt = &step
	r.FailureReason = reason
}

func (r *FlowResult) MarkSuccess() {
	r.Success = true
}

func (r *FlowResult) GetPath() []string {
	path := make([]string, len(r.Steps))
	for i, step := range r.Steps {
		path[i] = step.ComponentID
	}
	return path
}

func (r *FlowResult) GetComponentTypes() []string {
	types := make([]string, len(r.Steps))
	for i, step := range r.Steps {
		types[i] = step.ComponentType
	}
	return types
}

func (r *FlowResult) FindStepByComponent(componentID string) *FlowStep {
	for i, step := range r.Steps {
		if step.ComponentID == componentID {
			return &r.Steps[i]
		}
	}
	return nil
}

func (r *FlowResult) GetBlockingComponent() string {
	if r.BlockedAt != nil {
		return r.BlockedAt.ComponentID
	}
	return ""
}

func (r *FlowResult) HasRuleEvaluations() bool {
	for _, step := range r.Steps {
		if len(step.RuleChecks) > 0 {
			return true
		}
	}
	return false
}
