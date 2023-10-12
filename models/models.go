package models

import (
	"github.com/golang-jwt/jwt"
)

type LogTokenInfo struct {
	UserId   string
	ClientId string
}

type LNDhubClaims struct {
	ID        int64 `json:"id"`
	IsRefresh bool  `json:"isRefresh"`
	jwt.StandardClaims
}
