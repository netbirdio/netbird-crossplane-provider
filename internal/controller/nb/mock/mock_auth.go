package mock

import (
	"context"
	"sync"

	"github.com/go-logr/logr"
	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/pkg/errors"
)

// MockAuthManager is a mock implementation of auth.AuthManager
type MockAuthManager struct {
	mu            sync.Mutex
	MockGetClient func(ctx context.Context) (*rest.Client, error)
	log           logr.Logger
}

// NewMockAuthManager creates a new MockAuthManager
func NewMockAuthManager() *MockAuthManager {
	return &MockAuthManager{
		log: logr.Discard(),
	}
}

// GetClient returns a mock client
func (m *MockAuthManager) GetClient(ctx context.Context) (*rest.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.MockGetClient != nil {
		return m.MockGetClient(ctx)
	}
	return nil, errors.New("MockGetClient not implemented")
}

// WithGetClient sets the MockGetClient function
func (m *MockAuthManager) WithGetClient(fn func(ctx context.Context) (*rest.Client, error)) *MockAuthManager {
	m.MockGetClient = fn
	return m
}

// WithLogger sets the logger
func (m *MockAuthManager) WithLogger(log logr.Logger) *MockAuthManager {
	m.log = log
	return m
}
