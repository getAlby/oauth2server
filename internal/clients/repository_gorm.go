package clients

import (
	"context"
	"oauth2server/models"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	mdls "github.com/go-oauth2/oauth2/v4/models"
	"gorm.io/gorm"
)

type gormClientStore struct {
	db *gorm.DB
	cs *oauth2gorm.ClientStore
}

// UpdateClient implements ClientStore.
func (store *gormClientStore) UpdateClient(clientId, name, imageUrl, url string) (err error) {
	found := &models.ClientMetaData{}
	err = store.db.FirstOrCreate(found, &models.ClientMetaData{ClientID: clientId}).Error
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
func (store *gormClientStore) ListAllClients() (result []models.ClientMetaData, err error) {
	result = []models.ClientMetaData{}
	err = store.db.Find(&result, &models.ClientMetaData{}).Error
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
	return store.db.Create(&models.ClientMetaData{
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
