package domain

type HopAction string

const (
	HopActionAllowed   HopAction = "allowed"
	HopActionBlocked   HopAction = "blocked"
	HopActionRouted    HopAction = "routed"
	HopActionForwarded HopAction = "forwarded"
	HopActionResolved  HopAction = "resolved"
	HopActionTerminal  HopAction = "terminal"
	HopActionEntered   HopAction = "entered"
)

type ComponentHop struct {
	ComponentID   string
	ComponentType string
	AccountID     string

	SourceID     string
	SourceType   string
	Relationship string

	Action  HopAction
	Details string
}

type PathTrace struct {
	Hops      []*ComponentHop
	Success   bool
	BlockedAt *ComponentHop
}

func NewPathTrace() *PathTrace {
	return &PathTrace{
		Hops:    make([]*ComponentHop, 0),
		Success: false,
	}
}

func NewComponentHop(componentID, componentType, accountID string) *ComponentHop {
	return &ComponentHop{
		ComponentID:   componentID,
		ComponentType: componentType,
		AccountID:     accountID,
	}
}

func (h *ComponentHop) WithLineage(sourceID, sourceType, relationship string) *ComponentHop {
	h.SourceID = sourceID
	h.SourceType = sourceType
	h.Relationship = relationship
	return h
}

func (h *ComponentHop) WithAction(action HopAction, details string) *ComponentHop {
	h.Action = action
	h.Details = details
	return h
}

func (p *PathTrace) AddHop(hop *ComponentHop) *PathTrace {
	p.Hops = append(p.Hops, hop)
	return p
}

func (p *PathTrace) LastHop() *ComponentHop {
	if len(p.Hops) == 0 {
		return nil
	}
	return p.Hops[len(p.Hops)-1]
}

func (p *PathTrace) Clone() *PathTrace {
	newHops := make([]*ComponentHop, len(p.Hops))
	copy(newHops, p.Hops)
	return &PathTrace{
		Hops:      newHops,
		Success:   p.Success,
		BlockedAt: p.BlockedAt,
	}
}

func (p *PathTrace) MarkBlocked(reason string) *PathTrace {
	if last := p.LastHop(); last != nil {
		last.Action = HopActionBlocked
		last.Details = reason
		p.BlockedAt = last
	}
	p.Success = false
	return p
}

func (p *PathTrace) MarkSuccess() *PathTrace {
	p.Success = true
	p.BlockedAt = nil
	return p
}

func (p *PathTrace) GetBlockingReason() string {
	if p.Success || p.BlockedAt == nil {
		return ""
	}
	return "Blocked at " + p.BlockedAt.ComponentType + " " + p.BlockedAt.ComponentID + ": " + p.BlockedAt.Details
}

func (p *PathTrace) Depth() int {
	return len(p.Hops)
}

type HopLineage struct {
	SourceID     string
	SourceType   string
	Relationship string
}

func NewHopLineage(sourceID, sourceType, relationship string) HopLineage {
	return HopLineage{
		SourceID:     sourceID,
		SourceType:   sourceType,
		Relationship: relationship,
	}
}

func HopFromComponent(c Component, lineage HopLineage, action HopAction, details string) *ComponentHop {
	return &ComponentHop{
		ComponentID:   c.GetID(),
		ComponentType: c.GetComponentType(),
		AccountID:     c.GetAccountID(),
		SourceID:      lineage.SourceID,
		SourceType:    lineage.SourceType,
		Relationship:  lineage.Relationship,
		Action:        action,
		Details:       details,
	}
}
