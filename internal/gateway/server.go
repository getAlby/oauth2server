package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"oauth2server/models"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/sirupsen/logrus"
)

var errorResponses = map[string]int{
	errors.ErrExpiredAccessToken.Error():  http.StatusUnauthorized,
	errors.ErrExpiredRefreshToken.Error(): http.StatusUnauthorized,
	errors.ErrInvalidAccessToken.Error():  http.StatusUnauthorized,
	errors.ErrInvalidRefreshToken.Error(): http.StatusUnauthorized,
}

type OriginServer struct {
	Origin         string `json:"origin,omitempty"`
	proxy          http.Handler
	Scope          string `json:"scope"`
	MatchRoute     string `json:"matchRoute"`
	Method         string `json:"method"`
	Description    string `json:"description"`
	CheckTokenFunc func(context.Context, string) (oauth2.TokenInfo, error)
	JWTInjectFunc  func(ti oauth2.TokenInfo, r *http.Request) error
}

func (origin *OriginServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//check authorization
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenInfo, err := origin.CheckTokenFunc(r.Context(), token)
	if err != nil {
		if status, found := errorResponses[err.Error()]; found {
			writeErrorResponse(w, err.Error(), status)
		} else {
			logrus.Errorf("Something went wrong loading access token: %s, token %s, request %v, origin %v", err.Error(), token, r, origin)
			sentry.CaptureException(err)
			writeErrorResponse(w, "Something went wrong while authenticating user.", http.StatusInternalServerError)
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
		writeErrorResponse(w, fmt.Sprintf("Token does not have the right scope for operation: token scope %s, endpoint scope %s", tokenInfo.GetScope(), origin.Scope), http.StatusUnauthorized)
		return
	}

	err = origin.JWTInjectFunc(tokenInfo, r)
	if err != nil {
		logrus.Errorf("Something went wrong generating lndhub token: %s", err.Error())
		sentry.CaptureException(err)
		writeErrorResponse(w, "Something went wrong while authenticating user", http.StatusInternalServerError)
		return
	}

	lti := r.Context().Value("token_info")
	if lti != nil {
		logTokenInfo := lti.(*models.LogTokenInfo)
		logTokenInfo.UserId = tokenInfo.GetUserID()
		logTokenInfo.ClientId = tokenInfo.GetClientID()
	}

	origin.proxy.ServeHTTP(w, r)
}

func writeErrorResponse(w http.ResponseWriter, msg string, status int) {
	w.Header().Add("Content-type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"error":  msg,
	})
	if err != nil {
		logrus.Error(err)
	}
}
