package analyzer

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"

	awspkg "github.com/eleven-am/argus/internal/aws"
	"github.com/eleven-am/argus/internal/domain"
	resolverpkg "github.com/eleven-am/argus/internal/resolver"
)

func TestReachabilityDefault(ctx context.Context, source, destination domain.Component, awsCfg aws.Config, roleARNPattern string) domain.ReachabilityResult {
	accountCtx := awspkg.NewAccountContext(awsCfg, roleARNPattern)
	resolver := resolverpkg.NewResolver(accountCtx)
	return TestReachabilityWithResolver(ctx, source, destination, accountCtx, resolver)
}
