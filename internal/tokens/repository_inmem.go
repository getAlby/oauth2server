package tokens

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-oauth2/oauth2/v4"
)

type InMem struct {
	mtx    sync.Mutex
	tokens map[string]oauth2.TokenInfo
}

// Create implements oauth2.TokenStore.
func (im *InMem) Create(ctx context.Context, info oauth2.TokenInfo) error {
	im.mtx.Lock()
	im.tokens[info.GetAccess()] = info
	im.mtx.Unlock()
	return nil
}

// GetByAccess implements oauth2.TokenStore.
func (im *InMem) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	return im.tokens[access], nil
}

// GetByCode implements oauth2.TokenStore.
func (im *InMem) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	for _, token := range im.tokens {
		if token.GetCode() == code {
			return token, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

// GetByRefresh implements oauth2.TokenStore.
func (im *InMem) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	for _, token := range im.tokens {
		if token.GetRefresh() == refresh {
			return token, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

// RemoveByAccess implements oauth2.TokenStore.
func (im *InMem) RemoveByAccess(ctx context.Context, access string) error {
	for _, token := range im.tokens {
		if token.GetAccess() == access {
			delete(im.tokens, token.GetAccess())
			return nil
		}
	}
	return nil
}

// RemoveByCode implements oauth2.TokenStore.
func (im *InMem) RemoveByCode(ctx context.Context, code string) error {
	for _, token := range im.tokens {
		if token.GetCode() == code {
			delete(im.tokens, token.GetAccess())
			return nil
		}
	}
	return nil
}

// RemoveByRefresh implements oauth2.TokenStore.
func (im *InMem) RemoveByRefresh(ctx context.Context, refresh string) error {
	for _, token := range im.tokens {
		if token.GetRefresh() == refresh {
			delete(im.tokens, token.GetAccess())
			return nil
		}
	}
	return nil
}

func NewInmemStore() oauth2.TokenStore {
	return &InMem{
		mtx:    sync.Mutex{},
		tokens: map[string]oauth2.TokenInfo{},
	}
}
