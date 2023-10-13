package tokens

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
)

func initOauthServer(conf Config, cs oauth2.ClientStore, ts oauth2.TokenStore) (srv *server.Server, err error) {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	manager.MapClientStorage(cs)
	manager.MapTokenStorage(ts)

	manager.SetValidateURIHandler(checkRedirectUriDomain)

	manager.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    time.Duration(conf.AccessTokenExpSeconds) * time.Second,
		RefreshTokenExp:   time.Duration(conf.RefreshTokenExpSeconds) * time.Second,
		IsGenerateRefresh: true,
	})

	//use the default refresh config but add the reset refresh time = true
	//otherwise refreshing will always break after the token birthday + refresh token exiry
	manager.SetRefreshTokenCfg(
		&manage.RefreshingConfig{
			IsGenerateRefresh:  true,
			IsRemoveAccess:     true,
			IsRemoveRefreshing: true,
			IsResetRefreshTime: true,
		})

	srv = server.NewServer(server.NewConfig(), manager)
	srv.ClientInfoHandler = combinedClientInfoHandler
	srv.AccessTokenExpHandler = func(w http.ResponseWriter, r *http.Request) (exp time.Duration, err error) {
		return accessTokenExpHandler(r, conf.AccessTokenExpSeconds)
	}
	return srv, nil
}

func accessTokenExpHandler(r *http.Request, expirySeconds int) (exp time.Duration, err error) {
	expiry := r.FormValue("expires_in")
	if expiry != "" {
		expiresIn, err := strconv.Atoi(expiry)
		if err != nil {
			return time.Duration(0), err
		}
		return time.Duration(expiresIn) * time.Second, nil
	}
	return time.Duration(expirySeconds) * time.Second, nil
}

func combinedClientInfoHandler(r *http.Request) (clientID, clientSecret string, err error) {
	clientID, clientSecret, err = server.ClientBasicHandler(r)
	if err != nil {
		return server.ClientFormHandler(r)
	}
	return
}

func checkRedirectUriDomain(baseURI, redirectURI string) error {
	parsedClientUri, err := url.Parse(baseURI)
	if err != nil {
		return err
	}
	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil {
		return err
	}
	if parsedClientUri.Host != parsedRedirect.Host || parsedClientUri.Scheme != parsedRedirect.Scheme {
		err = fmt.Errorf("Wrong Redirect URI. Provided: [ Scheme: %s, Host: %s ], Expected: [ Scheme: %s, Host: %s ]", parsedRedirect.Scheme, parsedRedirect.Host, parsedClientUri.Scheme, parsedClientUri.Host)
		sentry.CaptureException(err)
		return err
	}
	return nil
}
