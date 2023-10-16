package clients

import (
	"context"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	oauth2 "github.com/go-oauth2/oauth2/v4"
	mdls "github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

const (
	TokenTableName  = "oauth2_tokens"
	ClientTableName = "oauth2_clients"
)

type gormClientStore struct {
	db *gorm.DB
	cs *oauth2gorm.ClientStore
}

// GetByID implements ClientStore.
func (store *gormClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	return store.cs.GetByID(ctx, id)
}

// DeleteClient implements ClientStore.
func (store *gormClientStore) DeleteClient(clientId string) error {
	return store.db.Table(TokenTableName).Delete(&oauth2gorm.TokenStoreItem{}, &oauth2gorm.TokenStoreItem{ClientID: clientId}).Error
}

// GetTokensForUser implements ClientStore.
func (store *gormClientStore) GetTokensForUser(userId string) (result []oauth2gorm.TokenStoreItem, err error) {
	result = []oauth2gorm.TokenStoreItem{}
	err = store.db.Table(TokenTableName).Find(&result, &oauth2gorm.TokenStoreItem{
		UserID: userId,
	}).Error
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetClient implements ClientStore.
func (store *gormClientStore) GetClient(clientId string) (result *ClientMetaData, err error) {
	result = &ClientMetaData{}
	err = store.db.First(result, &ClientMetaData{ClientID: clientId}).Error
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateClient implements ClientStore.
func (store *gormClientStore) UpdateClient(clientId, name, imageUrl, url string) (err error) {
	found := &ClientMetaData{}
	err = store.db.FirstOrCreate(found, &ClientMetaData{ClientID: clientId}).Error
	if err != nil {
		return err
	}
	if name != "" {
		found.Name = name
	}
	if imageUrl != "" {
		found.ImageUrl = imageUrl
	}
	if url != "" {
		found.URL = url
	}
	return store.db.Save(found).Error
}

// ListAllClients implements ClientStore.
func (store *gormClientStore) ListAllClients() (result []ClientMetaData, err error) {
	result = []ClientMetaData{}
	err = store.db.Find(&result, &ClientMetaData{}).Error
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (store *gormClientStore) Create(ctx context.Context, id string, secret string, domain string, url string, imageUrl, name string) error {
	err := store.cs.Create(ctx, &mdls.Client{
		ID:     id,
		Secret: secret,
		Domain: domain,
	})
	if err != nil {
		return err
	}
	return store.db.Create(&ClientMetaData{
		ClientID: id,
		Name:     name,
		ImageUrl: imageUrl,
		URL:      url,
	}).Error
}

func NewGormClientStore(db *gorm.DB, cs *oauth2gorm.ClientStore) ClientStore {
	return &gormClientStore{
		db: db,
		cs: cs,
	}
}
