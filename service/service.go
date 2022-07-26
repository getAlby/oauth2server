package service

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"oauth2server/models"
	"strconv"
	"time"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"
)

type Service struct {
	OauthServer *server.Server
	Config      *Config
	ClientStore *oauth2gorm.ClientStore
	DB          *gorm.DB
	Scopes      map[string]string
}

func (svc *Service) InitGateways() (result []*OriginServer, err error) {
	targetBytes, err := ioutil.ReadFile(svc.Config.TargetFile)
	if err != nil {
		return nil, err
	}
	result = []*OriginServer{}
	err = json.Unmarshal(targetBytes, &result)
	if err != nil {
		return nil, err
	}
	svc.Scopes = map[string]string{}
	originHelperMap := map[string]*httputil.ReverseProxy{}
	for _, origin := range result {
		origin.svc = svc
		svc.Scopes[origin.Scope] = origin.Description
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

func (svc *Service) InjectJWTAccessToken(token oauth2.TokenInfo, r *http.Request) error {
	//mint and inject jwt token needed for origin server
	//the request is dispatched immediately, so the tokens can have a short expiry
	expirySeconds := 60
	lndhubId := token.GetUserID()
	lndhubToken, err := GenerateLNDHubAccessToken(svc.Config.JWTSecret, expirySeconds, lndhubId)
	if err != nil {
		return err
	}
	//inject lndhub token in request
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", lndhubToken))
	return nil
}

// GenerateAccessToken : Generate Access Token
func GenerateLNDHubAccessToken(secret []byte, expiryInSeconds int, userId string) (string, error) {
	//convert string to int
	id, err := strconv.Atoi(userId)
	if err != nil {
		return "", err
	}
	claims := &models.LNDhubClaims{
		ID: int64(id),
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
