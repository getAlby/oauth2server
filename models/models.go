package models

import (
	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"
)

type ListClientsResponse struct {
	Domain   string            `json:"domain,omitempty"`
	ID       string            `json:"id,omitempty"`
	Name     string            `json:"name,omitempty"`
	ImageURL string            `json:"imageUrl,omitempty"`
	URL      string            `json:"url,omitempty"`
	Scopes   map[string]string `json:"scopes,omitempty"`
}

type CreateClientRequest struct {
	Domain   string `json:"domain"`
	UserID   string `json:"userId"`
	Name     string `json:"name"`
	ImageUrl string `json:"imageUrl"`
	URL      string `json:"url,omitempty"`
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
	ImageUrl     string `json:"imageUrl"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}
type LNDhubClaims struct {
	ID        int64 `json:"id"`
	IsRefresh bool  `json:"isRefresh"`
	jwt.StandardClaims
}