package clients

import (
	"context"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
)

type InMem struct {
	metadata map[string]ClientMetaData
	secrets  map[string]oauth2gorm.ClientStoreItem
}

// Create implements ClientStore.
func (*InMem) Create(ctx context.Context, id string, secret string, domain string, url string, imageUrl string, name string) error {
	panic("unimplemented")
}

// DeleteClient implements ClientStore.
func (*InMem) DeleteClient(clientId string) error {
	panic("unimplemented")
}

// GetClient implements ClientStore.
func (*InMem) GetClient(clientId string) (result *ClientMetaData, err error) {
	panic("unimplemented")
}

// GetTokensForUser implements ClientStore.
func (*InMem) GetTokensForUser(userId string) (result []oauth2gorm.TokenStoreItem, err error) {
	panic("unimplemented")
}

// ListAllClients implements ClientStore.
func (*InMem) ListAllClients() (result []ClientMetaData, err error) {
	panic("unimplemented")
}

// UpdateClient implements ClientStore.
func (*InMem) UpdateClient(clientId string, name string, imageUrl string, url string) (err error) {
	panic("unimplemented")
}

func NewInMem() ClientStore {
	return &InMem{
		metadata: map[string]ClientMetaData{},
		secrets:  map[string]oauth2gorm.ClientStoreItem{},
	}
}
