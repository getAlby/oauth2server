package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
)

type OriginServer struct {
	Origin      string `json:"origin"`
	svc         *Service
	proxy       *httputil.ReverseProxy
	Scope       string `json:"scope"`
	MatchRoute  string `json:"matchRoute"`
	Description string `json:"description"`
}

func (origin *OriginServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//check authorization
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenInfo, err := origin.svc.oauthServer.Manager.LoadAccessToken(r.Context(), token)
	if err != nil {
		logrus.Errorf("Something went wrong loading access token: %s, token %s, request %v", err.Error(), token, r)
		sentry.CaptureException(err)
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("Something went wrong while authenticating user."))
		if err != nil {
			logrus.Error(err)
		}
		return
	}
	//check scope
	allowed := false
	for _, sc := range strings.Split(tokenInfo.GetScope(), " ") {
		if sc == origin.Scope {
			allowed = true
			break
		}
	}
	if !allowed {
		w.WriteHeader(http.StatusUnauthorized)
		_, err = w.Write([]byte("Token does not have the right scope for operation"))
		if err != nil {
			logrus.Error(err)
		}
		return
	}

	err = origin.svc.InjectJWTAccessToken(tokenInfo, r)
	if err != nil {
		logrus.Errorf("Something went wrong generating lndhub token: %s", err.Error())
		sentry.CaptureException(err)
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("Something went wrong while authenticating user."))
		if err != nil {
			logrus.Error(err)
		}
		return
	}
	origin.proxy.ServeHTTP(w, r)
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
