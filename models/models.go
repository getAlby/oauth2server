package models

import (
	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"
)

type LogTokenInfo struct {
	UserId string
	ClientId string
}

type ListClientsResponse struct {
	Domain   string            `json:"domain,omitempty"`
	ID       string            `json:"id,omitempty"`
	Name     string            `json:"name,omitempty"`
	ImageURL string            `json:"imageUrl,omitempty"`
	URL      string            `json:"url,omitempty"`
	Scopes   map[string]string `json:"scopes,omitempty"`
}

type CreateClientRequest struct {
	Domain   string `json:"domain" validate:"required,uri"`
	UserID   string `json:"userId"`
	Name     string `json:"name" validate:"required"`
	ImageUrl string `json:"imageUrl"`
	URL      string `json:"url,omitempty"`
	Public   bool   `json:"public"`
}

type ClientMetaData struct {
	gorm.Model
	ClientID string `json:"clientId,omitempty"`
	Name     string `json:"name"`
	ImageUrl string `json:"imageUrl"`
	URL      string `json:"url,omitempty"`
}

type CreateClientResponse struct {
	Name         string `json:"name"`
	Url          string `json:"url"`
	ImageUrl     string `json:"imageUrl"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret,omitempty"`
}
type LNDhubClaims struct {
	ID        int64  `json:"id"`
	ClientId  string `json:"clientId"`
	IsRefresh bool   `json:"isRefresh"`
	jwt.StandardClaims
}
