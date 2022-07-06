package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
)

func (ctrl *OAuthController) ApiGateway(w http.ResponseWriter, r *http.Request) {
	//check authorization
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenInfo, err := ctrl.oauthServer.Manager.LoadAccessToken(r.Context(), token)
	if err != nil {
		logrus.Errorf("Something went wrong loading access token: %s, token %s, request %v", err.Error(), token, r)
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("Something went wrong while authenticating user."))
		if err != nil {
			logrus.Error(err)
		}
		return
	}
	//check scope
	//construct helper map
	allowedRoutes := map[string]bool{}
	for _, sc := range strings.Split(tokenInfo.GetScope(), " ") {
		allowedRoutes[scopes[sc][0]] = true
	}
	//check if route is allowed
	if _, found := allowedRoutes[r.URL.Path]; !found {
		w.WriteHeader(http.StatusUnauthorized)
		_, err = w.Write([]byte("Token does not have the right scope for operation"))
		if err != nil {
			logrus.Error(err)
		}
		return
	}
	//extract first part of path
	//eg. /ln/v2/balance -> /ln
	firstPathSegment := strings.Split(r.URL.Path, "/")[1]
	firstPathSegment = fmt.Sprintf("/%s", firstPathSegment)
	originServer := ctrl.service.gateways[firstPathSegment]
	err = originServer.headerInjectFunc(tokenInfo, r)
	if err != nil {
		logrus.Errorf("Something went wrong generating lndhub token: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("Something went wrong while authenticating user."))
		if err != nil {
			logrus.Error(err)
		}
		return
	}
	//trim first path segment first, the origin server does not know about it
	r.URL.Path = strings.TrimPrefix(r.URL.Path, firstPathSegment)
	//route to origin server
	originServer.proxy.ServeHTTP(w, r)
}

func (svc *Service) InjectGetalbycomHeader(token oauth2.TokenInfo, r *http.Request) error {
	//extract lndhub login from the stored double id
	lndhubLogin := strings.Split(token.GetUserID(), "_")[1]
	//set in header
	r.Header.Set("UserID", lndhubLogin)
	r.SetBasicAuth(svc.Config.GetalbyComUsername, svc.Config.GetalbyComPassword)
	return nil
}

func (svc *Service) InjectLNDhubAccessToken(token oauth2.TokenInfo, r *http.Request) error {
	//mint and inject jwt token needed for origin server
	//the request is dispatched immediately, so the tokens can have a short expiry
	expirySeconds := 60
	//extract right id from the stored "double" id
	lndhubId := strings.Split(token.GetUserID(), "_")[0]
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
	claims := &LNDhubClaims{
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

type LNDhubClaims struct {
	ID        int64 `json:"id"`
	IsRefresh bool  `json:"isRefresh"`
	jwt.StandardClaims
}
