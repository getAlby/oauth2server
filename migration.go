package main

import (
	"encoding/json"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	"github.com/go-oauth2/oauth2/models"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func MigrateTokenData(db *gorm.DB) error {
	tokens := []oauth2gorm.TokenStoreItem{}
	db.Table(tokenTableName).Find(&tokens)
	logrus.Info("Starting token data migration")
	for _, token := range tokens {
		//migrate json data to seperate columns
		ti := toTokenInfo(token.Data)
		token.ClientID = ti.GetClientID()
		token.RedirectURI = ti.GetRedirectURI()
		token.UserID = ti.GetUserID()
		tx := db.Table(tokenTableName).Save(&token)
		if tx.Error != nil {
			return tx.Error
		}

	}
	logrus.Info("Token data migration finished")
	return nil
}

func toTokenInfo(data string) *models.Token {
	var tm models.Token
	err := json.Unmarshal([]byte(data), &tm)
	if err != nil {
		return nil
	}
	return &tm
}
