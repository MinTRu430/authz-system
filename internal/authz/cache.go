package authz

import (
	"sync"
	"time"
)

type cacheKey struct{ src, tgt, method string }
type cacheVal struct {
	resp      CheckResponse
	expiresAt time.Time
}

type DecisionCache struct {
	mu   sync.RWMutex
	ttl  time.Duration
	data map[cacheKey]cacheVal
}

func NewDecisionCache(ttl time.Duration) *DecisionCache {
	if ttl <= 0 {
		ttl = 2 * time.Second
	}
	return &DecisionCache{ttl: ttl, data: map[cacheKey]cacheVal{}}
}

func (c *DecisionCache) Get(src, tgt, method string) (CheckResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	k := cacheKey{src, tgt, method}
	v, ok := c.data[k]
	if !ok || time.Now().After(v.expiresAt) {
		return CheckResponse{}, false
	}
	return v.resp, true
}

func (c *DecisionCache) Put(src, tgt, method string, resp CheckResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[cacheKey{src, tgt, method}] = cacheVal{resp: resp, expiresAt: time.Now().Add(c.ttl)}
}
