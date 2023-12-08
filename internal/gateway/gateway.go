package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/golang-jwt/jwt"
)

func InitGateways(targetFile string,
	tokenFunc func(context.Context, string) (oauth2.TokenInfo, error),
	jwtSecret []byte,
) (result []*OriginServer, err error) {
	targetBytes, err := os.ReadFile(targetFile)
	if err != nil {
		return nil, err
	}
	result = []*OriginServer{}
	err = json.Unmarshal(targetBytes, &result)
	if err != nil {
		return nil, err
	}
	originHelperMap := map[string]http.Handler{}
	for _, origin := range result {
		origin.JWTInjectFunc = func(ti oauth2.TokenInfo, r *http.Request) error {
			return InjectJWTAccessToken(ti, r, jwtSecret)
		}
		origin.CheckTokenFunc = tokenFunc
		//avoid creating too much identical origin server objects
		//by storing them in a map
		value, found := originHelperMap[origin.Origin]
		if found {
			//use existing one
			origin.proxy = value
		} else {
			//create new one
			originUrl, err := url.Parse(origin.Origin)
			if err != nil {
				return nil, err
			}
			proxy := httputil.NewSingleHostReverseProxy(originUrl)
			originHelperMap[origin.Origin] = proxy
			origin.proxy = proxy
		}
	}
	return result, nil
}

func InjectJWTAccessToken(token oauth2.TokenInfo, r *http.Request, secret []byte) error {
	//mint and inject jwt token needed for origin server
	//the request is dispatched immediately, so the tokens can have a short expiry
	expirySeconds := 60
	lndhubId := token.GetUserID()
	clientId := token.GetClientID()
	lndhubToken, err := generateLNDHubAccessToken(secret, expirySeconds, lndhubId, clientId)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", lndhubToken))
	return nil
}

// GenerateAccessToken : Generate Access Token
func generateLNDHubAccessToken(secret []byte, expiryInSeconds int, userId, clientId string) (string, error) {
	//convert string to int
	id, err := strconv.Atoi(userId)
	if err != nil {
		return "", err
	}
	claims := &LNDhubClaims{
		ID:       int64(id),
		ClientId: clientId,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * time.Duration(expiryInSeconds)).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return t, nil
}

type LNDhubClaims struct {
	ID        int64  `json:"id"`
	IsRefresh bool   `json:"isRefresh"`
	ClientId  string `json:"clientId"`
	jwt.StandardClaims
}
