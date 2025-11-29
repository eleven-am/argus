package components

import (
	"fmt"

	"github.com/eleven-am/argus/internal/domain"
)

type Subnet struct {
	data      *domain.SubnetData
	accountID string
}

func NewSubnet(data *domain.SubnetData, accountID string) *Subnet {
	return &Subnet{
		data:      data,
		accountID: accountID,
	}
}

func (s *Subnet) GetNextHops(dest domain.RoutingTarget, analyzerCtx domain.AnalyzerContext) ([]domain.Component, error) {
	client, err := analyzerCtx.GetAccountContext().GetClient(s.accountID)
	if err != nil {
		return nil, err
	}

	ctx := analyzerCtx.Context()

	rtData, err := client.GetRouteTable(ctx, s.data.RouteTableID)
	if err != nil {
		return nil, err
	}
	routeTable := NewRouteTable(rtData, s.accountID)

	naclData, err := client.GetNACL(ctx, s.data.NaclID)
	if err != nil {
		return nil, err
	}
	nacl := NewNACLWithNext(naclData, s.accountID, routeTable)

	return []domain.Component{nacl}, nil
}

func (s *Subnet) GetRoutingTarget() domain.RoutingTarget {
	return domain.RoutingTarget{}
}

func (s *Subnet) GetID() string {
	return fmt.Sprintf("%s:%s", s.accountID, s.data.ID)
}

func (s *Subnet) GetAccountID() string {
	return s.accountID
}

func (s *Subnet) GetComponentType() string {
	return "Subnet"
}
