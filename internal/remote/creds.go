package remote

import (
	"fmt"
	"sync"
)

// Credentials hold the secret material used to connect to a target.
//
// They are stored in-memory only by the CredentialCache; the Store never
// persists them to disk.
type Credentials struct {
	Username string
	Password []byte
	KeyPath  string
}

// CredentialCache is an in-memory keyed cache of Credentials. It is safe for
// concurrent use.
//
// Keys are formed as "{hostname}:{protocol}" so the same host accessed via
// SSH and WinRM gets distinct entries.
type CredentialCache struct {
	mu    sync.RWMutex
	store map[string]Credentials
}

// NewCredentialCache returns an empty cache.
func NewCredentialCache() *CredentialCache {
	return &CredentialCache{store: map[string]Credentials{}}
}

// Key returns the cache key for a target.
func cacheKey(t *RemoteTarget) string {
	return fmt.Sprintf("%s:%s", t.Hostname, t.Protocol)
}

// Get returns the cached credentials for the target, or (zero, false).
func (c *CredentialCache) Get(t *RemoteTarget) (Credentials, bool) {
	if c == nil {
		return Credentials{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	creds, ok := c.store[cacheKey(t)]
	return creds, ok
}

// Put stores credentials for the target.
func (c *CredentialCache) Put(t *RemoteTarget, creds Credentials) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[cacheKey(t)] = creds
}

// Clear removes the credentials for one target.
func (c *CredentialCache) Clear(t *RemoteTarget) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, cacheKey(t))
}

// ClearAll wipes every cached credential. Called on app exit (or by an
// explicit "Clear cached credentials" UI action).
func (c *CredentialCache) ClearAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.store {
		delete(c.store, k)
	}
}
