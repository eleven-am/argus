package domain

import "fmt"

type PathResult interface {
	IsBlocked() bool
	GetBlockingReason() string
}

type SuccessResult struct{}

func (s SuccessResult) IsBlocked() bool           { return false }
func (s SuccessResult) GetBlockingReason() string { return "" }

type BlockedResult struct {
	BlockingComponent Component
	Reason            error
}

func (b BlockedResult) IsBlocked() bool { return true }
func (b BlockedResult) GetBlockingReason() string {
	return fmt.Sprintf("Blocked at %s: %s", b.BlockingComponent.GetID(), b.Reason.Error())
}

type ReachabilityResult struct {
	SourceToDestination PathResult
	DestinationToSource PathResult
	OverallSuccess      bool
	ForwardPath         *PathTrace
	ReturnPath          *PathTrace
}

func CombineResults(srcToDest, destToSrc PathResult) ReachabilityResult {
	return ReachabilityResult{
		SourceToDestination: srcToDest,
		DestinationToSource: destToSrc,
		OverallSuccess:      !srcToDest.IsBlocked() && !destToSrc.IsBlocked(),
	}
}

func CombineResultsWithTrace(srcToDest, destToSrc PathResult, forwardTrace, returnTrace *PathTrace) ReachabilityResult {
	return ReachabilityResult{
		SourceToDestination: srcToDest,
		DestinationToSource: destToSrc,
		OverallSuccess:      !srcToDest.IsBlocked() && !destToSrc.IsBlocked(),
		ForwardPath:         forwardTrace,
		ReturnPath:          returnTrace,
	}
}

type AllPathsResult struct {
	ForwardPaths           []*PathTrace
	ReturnPaths            []*PathTrace
	SuccessfulForwardPaths int
	SuccessfulReturnPaths  int
	HasReachablePath       bool
}

func (r *AllPathsResult) GetSuccessfulPaths() []*PathTrace {
	var successful []*PathTrace
	for _, p := range r.ForwardPaths {
		if p.Success {
			successful = append(successful, p)
		}
	}
	return successful
}

func (r *AllPathsResult) GetBlockedPaths() []*PathTrace {
	var blocked []*PathTrace
	for _, p := range r.ForwardPaths {
		if !p.Success {
			blocked = append(blocked, p)
		}
	}
	return blocked
}
