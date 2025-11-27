package tokenstore

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"sync"
	"time"
)

// TokenMapping stores the mapping between proxy token and real user token
type TokenMapping struct {
	RealToken string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// TokenStore manages proxy token to real token mappings
type TokenStore struct {
	mu              sync.RWMutex
	tokens          map[string]*TokenMapping
	logger          *slog.Logger
	ttl             time.Duration
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewTokenStore creates a new token store
func NewTokenStore(logger *slog.Logger, ttl time.Duration) *TokenStore {
	store := &TokenStore{
		tokens:          make(map[string]*TokenMapping),
		logger:          logger,
		ttl:             ttl,
		cleanupInterval: 5 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanup()

	return store
}

// GenerateProxyToken generates a secure random proxy token
func (ts *TokenStore) GenerateProxyToken() (string, error) {
	// Generate 32 random bytes (256 bits)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	// Base64 encode for URL-safe token
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	return token, nil
}

// Store stores a proxy token to real token mapping
func (ts *TokenStore) Store(proxyToken, realToken string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.tokens[proxyToken] = &TokenMapping{
		RealToken: realToken,
		ExpiresAt: time.Now().Add(ts.ttl),
		CreatedAt: time.Now(),
	}

	tokenPrefix := proxyToken
	if len(proxyToken) > 8 {
		tokenPrefix = proxyToken[:8] + "..."
	}
	ts.logger.Debug("Stored proxy token mapping", "proxy_token_prefix", tokenPrefix)
}

// Get retrieves the real token for a proxy token
func (ts *TokenStore) Get(proxyToken string) (string, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	mapping, exists := ts.tokens[proxyToken]
	if !exists {
		return "", false
	}

	// Check if token has expired
	if time.Now().After(mapping.ExpiresAt) {
		tokenPrefix := proxyToken
		if len(proxyToken) > 8 {
			tokenPrefix = proxyToken[:8] + "..."
		}
		ts.logger.Debug("Proxy token expired", "proxy_token_prefix", tokenPrefix)
		return "", false
	}

	return mapping.RealToken, true
}

// Delete removes a proxy token mapping
func (ts *TokenStore) Delete(proxyToken string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.tokens, proxyToken)
}

// cleanup periodically removes expired tokens
func (ts *TokenStore) cleanup() {
	ticker := time.NewTicker(ts.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ts.mu.Lock()
			now := time.Now()
			expiredCount := 0
			for token, mapping := range ts.tokens {
				if now.After(mapping.ExpiresAt) {
					delete(ts.tokens, token)
					expiredCount++
				}
			}
			ts.mu.Unlock()
			if expiredCount > 0 {
				ts.logger.Debug("Cleaned up expired tokens", "count", expiredCount)
			}
		case <-ts.stopCleanup:
			return
		}
	}
}

// Stop stops the cleanup goroutine
func (ts *TokenStore) Stop() {
	close(ts.stopCleanup)
}

// Size returns the number of stored tokens
func (ts *TokenStore) Size() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.tokens)
}
