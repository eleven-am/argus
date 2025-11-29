package aws

import (
	"sync"
	"time"
)

type cacheEntry struct {
	value    interface{}
	expires  time.Time
	inserted time.Time
}

type ttlCache struct {
	mu       sync.RWMutex
	ttl      time.Duration
	capacity int
	data     map[string]cacheEntry
}

func newTTLCache(ttl time.Duration, capacity int) *ttlCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if capacity <= 0 {
		capacity = 1000
	}
	return &ttlCache{
		ttl:      ttl,
		capacity: capacity,
		data:     make(map[string]cacheEntry),
	}
}

func (c *ttlCache) get(key string) (interface{}, bool) {
	c.mu.RLock()
	entry, ok := c.data[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expires) {
		c.mu.Lock()
		delete(c.data, key)
		c.mu.Unlock()
		return nil, false
	}
	return entry.value, true
}

func (c *ttlCache) set(key string, value interface{}) {
	c.mu.Lock()
	if len(c.data) >= c.capacity {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, v := range c.data {
			if first || v.inserted.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.inserted
				first = false
			}
		}
		delete(c.data, oldestKey)
	}
	c.data[key] = cacheEntry{
		value:    value,
		expires:  time.Now().Add(c.ttl),
		inserted: time.Now(),
	}
	c.mu.Unlock()
}
