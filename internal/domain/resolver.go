package domain

import "context"

type DestinationResolver interface {
	ResolveByIP(ctx context.Context, accountID, vpcID, ip string) (Component, error)
	ResolveByID(ctx context.Context, id string) (Component, error)
}

type ResolverProvider interface {
	GetResolver() DestinationResolver
}
