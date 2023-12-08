package clients

import (
	"context"
	"fmt"
	"sync"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
)

type InMem struct {
	mtx      sync.Mutex
	metadata map[string]ClientMetaData
	secrets  map[string]oauth2gorm.ClientStoreItem
	tokens   map[string]oauth2gorm.TokenStoreItem
}

// GetByID implements ClientStore.
func (im *InMem) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	client, ok := im.secrets[id]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return &models.Client{
		ID:     client.ID,
		Secret: client.Secret,
		Domain: client.Domain,
	}, nil
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
func (im *InMem) GetTokensForUser(userId string) (result []oauth2gorm.TokenStoreItem, err error) {
	result = []oauth2gorm.TokenStoreItem{}
	for _, t := range im.tokens {
		result = append(result, t)
	}
	return result, nil
}

// Create implements ClientStore.
func (im *InMem) AddToken(ctx context.Context, token oauth2gorm.TokenStoreItem) error {
	im.mtx.Lock()
	im.tokens[token.Access] = token
	im.mtx.Unlock()
	return nil
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
		mtx:      sync.Mutex{},
		metadata: map[string]ClientMetaData{},
		secrets:  map[string]oauth2gorm.ClientStoreItem{},
		tokens:   map[string]oauth2gorm.TokenStoreItem{},
	}
}
