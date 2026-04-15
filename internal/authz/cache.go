package authz

import (
	"sync"
	"time"
)

type cacheKey struct {
	source    string
	target    string
	transport Transport
	operation string
	resource  string
}

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

func newCacheKey(req AuthzRequest) cacheKey {
	req = req.Normalize()
	return cacheKey{
		source:    req.Source,
		target:    req.Target,
		transport: req.Transport,
		operation: req.Operation,
		resource:  req.Resource,
	}
}

func (c *DecisionCache) Get(req AuthzRequest) (CheckResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	k := newCacheKey(req)
	v, ok := c.data[k]
	if !ok || time.Now().After(v.expiresAt) {
		return CheckResponse{}, false
	}
	return v.resp, true
}

func (c *DecisionCache) Put(req AuthzRequest, resp CheckResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[newCacheKey(req)] = cacheVal{resp: resp, expiresAt: time.Now().Add(c.ttl)}
}
