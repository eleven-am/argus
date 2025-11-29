package aws

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/directconnect"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

type Client struct {
	ec2Client             *ec2.Client
	rdsClient             *rds.Client
	lambdaClient          *lambda.Client
	elbClient             *elb.Client
	elbv2Client           *elbv2.Client
	apigwClient           *apigateway.Client
	apigwv2Client         *apigatewayv2.Client
	elasticacheClient     *elasticache.Client
	directconnectClient   *directconnect.Client
	networkFirewallClient *networkfirewall.Client
	accountID             string
	region                string
	cache                 *ttlCache
}

func newRetryer() aws.Retryer {
	return retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = 5
		o.MaxBackoff = 30 * time.Second
		o.Backoff = retry.NewExponentialJitterBackoff(o.MaxBackoff)
		o.RateLimiter = ratelimit.None
	})
}

func NewClient(cfg aws.Config, accountID, region string) *Client {
	retryer := newRetryer()
	return &Client{
		ec2Client:             ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Retryer = retryer }),
		rdsClient:             rds.NewFromConfig(cfg, func(o *rds.Options) { o.Retryer = retryer }),
		lambdaClient:          lambda.NewFromConfig(cfg, func(o *lambda.Options) { o.Retryer = retryer }),
		elbClient:             elb.NewFromConfig(cfg, func(o *elb.Options) { o.Retryer = retryer }),
		elbv2Client:           elbv2.NewFromConfig(cfg, func(o *elbv2.Options) { o.Retryer = retryer }),
		apigwClient:           apigateway.NewFromConfig(cfg, func(o *apigateway.Options) { o.Retryer = retryer }),
		apigwv2Client:         apigatewayv2.NewFromConfig(cfg, func(o *apigatewayv2.Options) { o.Retryer = retryer }),
		elasticacheClient:     elasticache.NewFromConfig(cfg, func(o *elasticache.Options) { o.Retryer = retryer }),
		directconnectClient:   directconnect.NewFromConfig(cfg, func(o *directconnect.Options) { o.Retryer = retryer }),
		networkFirewallClient: networkfirewall.NewFromConfig(cfg, func(o *networkfirewall.Options) { o.Retryer = retryer }),
		accountID:             accountID,
		region:                region,
		cache:                 newTTLCache(5*time.Minute, 2000),
	}
}

func (c *Client) cacheKey(parts ...string) string {
	return strings.Join(parts, ":")
}
