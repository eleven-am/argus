package domain

type BlockingError struct {
	ComponentID string
	Reason      string
}

func (e *BlockingError) Error() string {
	return e.Reason
}
