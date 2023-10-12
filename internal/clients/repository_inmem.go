package clients

import (
	"context"
	"fmt"
	"sync"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
)

type InMem struct {
	mtx      sync.Mutex
	metadata map[string]ClientMetaData
	secrets  map[string]oauth2gorm.ClientStoreItem
}

// Create implements ClientStore.
func (im *InMem) Create(ctx context.Context, id string, secret string, domain string, url string, imageUrl string, name string) error {
	im.mtx.Lock()
	im.metadata[id] = ClientMetaData{
		ClientID: id,
		Name:     name,
		ImageUrl: imageUrl,
		URL:      url,
	}
	im.secrets[id] = oauth2gorm.ClientStoreItem{
		ID:     id,
		Secret: secret,
		Domain: domain,
	}
	im.mtx.Unlock()
	return nil
}

// DeleteClient implements ClientStore.
func (im *InMem) DeleteClient(clientId string) error {
	im.mtx.Lock()
	delete(im.secrets, clientId)
	delete(im.metadata, clientId)
	im.mtx.Unlock()
	return nil
}

// GetClient implements ClientStore.
func (im *InMem) GetClient(clientId string) (result *ClientMetaData, err error) {
	res, ok := im.metadata[clientId]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return &res, nil
}

// GetTokensForUser implements ClientStore.
func (*InMem) GetTokensForUser(userId string) (result []oauth2gorm.TokenStoreItem, err error) {
	return nil, fmt.Errorf("not implemented")
}

// ListAllClients implements ClientStore.
func (im *InMem) ListAllClients() (result []ClientMetaData, err error) {
	result = []ClientMetaData{}
	for _, v := range im.metadata {
		result = append(result, v)
	}
	return result, nil
}

// UpdateClient implements ClientStore.
func (im *InMem) UpdateClient(clientId string, name string, imageUrl string, url string) (err error) {
	im.mtx.Lock()
	toUpdate, ok := im.metadata[clientId]
	if !ok {
		return fmt.Errorf("not found")
	}
	if name != "" {
		toUpdate.Name = name
	}
	if imageUrl != "" {
		toUpdate.ImageUrl = imageUrl
	}
	if url != "" {
		toUpdate.URL = url
	}
	im.metadata[clientId] = toUpdate
	im.mtx.Unlock()
	return nil
}

func NewInMem() ClientStore {
	return &InMem{
		metadata: map[string]ClientMetaData{},
		secrets:  map[string]oauth2gorm.ClientStoreItem{},
	}
}
