package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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
		w.Write([]byte("Something went wrong while authenticating user."))
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
		w.Write([]byte("Token does not have the right scope for operation"))
		return
	}
	//mint and inject jwt token needed for origin server
	//the request is dispatched immediately, so the tokens can have a short expiry
	expirySeconds := 60
	//extract right id from the stored "double" id
	lndhubId := strings.Split(tokenInfo.GetUserID(), "_")[0]
	lndhubToken, err := GenerateLNDHubAccessToken(ctrl.service.Config.JWTSecret, expirySeconds, lndhubId)
	if err != nil {
		logrus.Errorf("Something went wrong generating lndhub token: %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Something went wrong while authenticating user."))
		return
	}
	//inject lndhub token in request
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", lndhubToken))
	//route to origin server
	ctrl.service.gateways["/v2/"].ServeHTTP(w, r)
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
