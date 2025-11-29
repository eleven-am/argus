package aws

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
)

func TestNewRetryer(t *testing.T) {
	retryer := newRetryer()

	if retryer == nil {
		t.Fatal("expected non-nil retryer")
	}

	if _, ok := retryer.(*retry.Standard); !ok {
		t.Error("expected retryer to be *retry.Standard")
	}
}

func TestNewRetryer_MaxAttempts(t *testing.T) {
	retryer := newRetryer()

	maxAttempts := retryer.MaxAttempts()
	if maxAttempts != 5 {
		t.Errorf("expected MaxAttempts = 5, got %d", maxAttempts)
	}
}

func TestNewRetryer_IsErrorRetryable(t *testing.T) {
	retryer := newRetryer()

	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "nil error",
			err:       nil,
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := retryer.IsErrorRetryable(tt.err)
			if result != tt.retryable {
				t.Errorf("IsErrorRetryable(%v) = %v, want %v", tt.err, result, tt.retryable)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	cfg := aws.Config{}
	client := NewClient(cfg, "123456789012", "us-east-1")

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	if client.accountID != "123456789012" {
		t.Errorf("expected accountID = 123456789012, got %s", client.accountID)
	}

	if client.region != "us-east-1" {
		t.Errorf("expected region = us-east-1, got %s", client.region)
	}

	if client.ec2Client == nil {
		t.Error("expected non-nil ec2Client")
	}

	if client.rdsClient == nil {
		t.Error("expected non-nil rdsClient")
	}

	if client.lambdaClient == nil {
		t.Error("expected non-nil lambdaClient")
	}

	if client.elbClient == nil {
		t.Error("expected non-nil elbClient")
	}

	if client.elbv2Client == nil {
		t.Error("expected non-nil elbv2Client")
	}

	if client.cache == nil {
		t.Error("expected non-nil cache")
	}
}

func TestTTLCache_SetAndGet(t *testing.T) {
	cache := newTTLCache(5*time.Minute, 100)

	cache.set("key1", "value1")

	val, ok := cache.get("key1")
	if !ok {
		t.Fatal("expected key1 to exist")
	}

	if val != "value1" {
		t.Errorf("expected value1, got %v", val)
	}
}

func TestTTLCache_GetMissing(t *testing.T) {
	cache := newTTLCache(5*time.Minute, 100)

	_, ok := cache.get("nonexistent")
	if ok {
		t.Error("expected key to not exist")
	}
}

func TestTTLCache_Expiration(t *testing.T) {
	cache := newTTLCache(50*time.Millisecond, 100)

	cache.set("key1", "value1")

	val, ok := cache.get("key1")
	if !ok {
		t.Fatal("expected key1 to exist immediately after set")
	}
	if val != "value1" {
		t.Errorf("expected value1, got %v", val)
	}

	time.Sleep(100 * time.Millisecond)

	_, ok = cache.get("key1")
	if ok {
		t.Error("expected key1 to be expired")
	}
}

func TestTTLCache_Capacity(t *testing.T) {
	cache := newTTLCache(5*time.Minute, 3)

	cache.set("key1", "value1")
	cache.set("key2", "value2")
	cache.set("key3", "value3")

	if _, ok := cache.get("key1"); !ok {
		t.Error("expected key1 to exist")
	}
	if _, ok := cache.get("key2"); !ok {
		t.Error("expected key2 to exist")
	}
	if _, ok := cache.get("key3"); !ok {
		t.Error("expected key3 to exist")
	}

	cache.set("key4", "value4")

	if _, ok := cache.get("key4"); !ok {
		t.Error("expected key4 to exist")
	}

	existingCount := 0
	for _, key := range []string{"key1", "key2", "key3"} {
		if _, ok := cache.get(key); ok {
			existingCount++
		}
	}

	if existingCount != 2 {
		t.Errorf("expected 2 of the original 3 keys to remain, got %d", existingCount)
	}
}

func TestTTLCache_Overwrite(t *testing.T) {
	cache := newTTLCache(5*time.Minute, 100)

	cache.set("key1", "value1")
	cache.set("key1", "value2")

	val, ok := cache.get("key1")
	if !ok {
		t.Fatal("expected key1 to exist")
	}

	if val != "value2" {
		t.Errorf("expected value2, got %v", val)
	}
}

func TestTTLCache_DefaultValues(t *testing.T) {
	cache := newTTLCache(0, 0)

	if cache.ttl != 5*time.Minute {
		t.Errorf("expected default TTL of 5 minutes, got %v", cache.ttl)
	}

	if cache.capacity != 1000 {
		t.Errorf("expected default capacity of 1000, got %d", cache.capacity)
	}
}

func TestCacheKey(t *testing.T) {
	cfg := aws.Config{}
	client := NewClient(cfg, "123456789012", "us-east-1")

	key := client.cacheKey("sg", "sg-12345")
	expected := "sg:sg-12345"

	if key != expected {
		t.Errorf("expected cache key %s, got %s", expected, key)
	}
}

func TestCacheKey_MultipleArgs(t *testing.T) {
	cfg := aws.Config{}
	client := NewClient(cfg, "123456789012", "us-east-1")

	key := client.cacheKey("tgw-attach", "vpc-123", "tgw-456")
	expected := "tgw-attach:vpc-123:tgw-456"

	if key != expected {
		t.Errorf("expected cache key %s, got %s", expected, key)
	}
}

func TestTTLCache_ConcurrentAccess(t *testing.T) {
	cache := newTTLCache(5*time.Minute, 1000)

	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				key := "key" + string(rune('0'+id))
				cache.set(key, id*100+j)
				cache.get(key)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
