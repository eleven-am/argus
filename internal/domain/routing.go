package domain

type RoutingTarget struct {
	IP       string
	Port     int
	Protocol string
	// Direction indicates the traversal leg perspective for filters.
	// Expected values: "outbound" or "inbound".
	Direction string
	// SourceIsPrivate indicates whether the source IP for this leg is private.
	SourceIsPrivate bool
}
