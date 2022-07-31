package service

import (
	"net/http"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/sirupsen/logrus"
)

type OriginServer struct {
	Origin      string `json:"origin"`
	svc         *Service
	proxy       http.Handler
	IsWebsocket bool   `json:"bool"`
	Scope       string `json:"scope"`
	MatchRoute  string `json:"matchRoute"`
	Description string `json:"description"`
}

func (origin *OriginServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//check authorization
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if origin.IsWebsocket {
		token = r.URL.Query().Get("token")
	}
	tokenInfo, err := origin.svc.OauthServer.Manager.LoadAccessToken(r.Context(), token)
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

	err = origin.svc.InjectJWTAccessToken(tokenInfo, r, origin.IsWebsocket)
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
