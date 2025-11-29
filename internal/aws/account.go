package aws

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/eleven-am/argus/internal/domain"
)

type credentialEntry struct {
	creds      domain.AWSCredentials
	expiration time.Time
}

type AccountContext struct {
	baseConfig      aws.Config
	roleARNPattern  string
	stsClient       *sts.Client
	credentialCache map[string]credentialEntry
	clientPool      map[string]*Client
	mu              sync.RWMutex
}

func NewAccountContext(cfg aws.Config, roleARNPattern string) *AccountContext {
	if roleARNPattern == "" {
		roleARNPattern = "arn:aws:iam::%s:role/ReachabilityAnalyzerCrossAccountRole"
	}
	return &AccountContext{
		baseConfig:      cfg,
		roleARNPattern:  roleARNPattern,
		stsClient:       sts.NewFromConfig(cfg),
		credentialCache: make(map[string]credentialEntry),
		clientPool:      make(map[string]*Client),
	}
}

func (a *AccountContext) AssumeRole(accountID string) (domain.AWSCredentials, error) {
	a.mu.RLock()
	entry, exists := a.credentialCache[accountID]
	a.mu.RUnlock()

	if exists && time.Now().Add(5*time.Minute).Before(entry.expiration) {
		return entry.creds, nil
	}

	roleARN := fmt.Sprintf(a.roleARNPattern, accountID)
	sessionName := fmt.Sprintf("reachability-analyzer-%s", accountID)

	out, err := a.stsClient.AssumeRole(context.Background(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(3600),
	})
	if err != nil {
		return domain.AWSCredentials{}, fmt.Errorf("assume role %s: %w", roleARN, err)
	}

	creds := domain.AWSCredentials{
		AccessKeyID:     derefString(out.Credentials.AccessKeyId),
		SecretAccessKey: derefString(out.Credentials.SecretAccessKey),
		SessionToken:    derefString(out.Credentials.SessionToken),
		Expiration:      *out.Credentials.Expiration,
	}

	a.mu.Lock()
	a.credentialCache[accountID] = credentialEntry{
		creds:      creds,
		expiration: creds.Expiration,
	}
	a.mu.Unlock()

	return creds, nil
}

func (a *AccountContext) GetClient(accountID string) (domain.AWSClient, error) {
	a.mu.RLock()
	client, exists := a.clientPool[accountID]
	a.mu.RUnlock()

	if exists {
		entry, hasEntry := a.credentialCache[accountID]
		if hasEntry && time.Now().Add(5*time.Minute).Before(entry.expiration) {
			return client, nil
		}
	}

	creds, err := a.AssumeRole(accountID)
	if err != nil {
		return nil, err
	}

	cfg := a.baseConfig.Copy()
	cfg.Credentials = credentials.NewStaticCredentialsProvider(
		creds.AccessKeyID,
		creds.SecretAccessKey,
		creds.SessionToken,
	)

	client = NewClient(cfg, accountID, cfg.Region)

	a.mu.Lock()
	a.clientPool[accountID] = client
	a.mu.Unlock()

	return client, nil
}
