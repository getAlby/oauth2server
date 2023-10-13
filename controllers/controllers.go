package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"oauth2server/service"
	"strings"

	"github.com/getsentry/sentry-go"
	oauthErrors "github.com/go-oauth2/oauth2/errors"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
)

type ctx_id_type string

var CONTEXT_ID_KEY ctx_id_type = "ID"

type OAuthController struct {
	Service *service.Service
}

func (ctrl *OAuthController) InternalErrorHandler(err error) (re *errors.Response) {
	//workaround to not show "sql: no rows in result set" to user
	sentry.CaptureException(err)
	description := oauthErrors.Descriptions[err]
	statusCode := oauthErrors.StatusCodes[err]
	if description != "" && statusCode != 0 {
		return &errors.Response{
			Error:       fmt.Errorf(description),
			ErrorCode:   statusCode,
			Description: description,
			URI:         "",
			StatusCode:  statusCode,
			Header:      map[string][]string{},
		}
	}
	return &errors.Response{
		Error:       err,
		ErrorCode:   0,
		Description: "",
		URI:         "",
		StatusCode:  500,
		Header:      map[string][]string{},
	}
}
func (ctrl *OAuthController) UserAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	token, err := ctrl.authenticateUser(r)
	if err != nil {
		logrus.Error(err)
		sentry.CaptureException(err)
		return "", err
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return ctrl.Service.Config.JWTSecret, nil
	})
	if err != nil {
		return "", err
	}
	if claims["id"] == nil {
		return "", fmt.Errorf("Cannot authenticate user, token does not contain user id")
	}
	return fmt.Sprintf("%.0f", claims["id"].(float64)), nil
}

func (ctrl *OAuthController) UserAuthorizeMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := ctrl.UserAuthorizeHandler(w, r)
		if err != nil {
			logrus.Errorf("Error authenticating user %s", err.Error())
			sentry.CaptureException(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), CONTEXT_ID_KEY, id))
		h.ServeHTTP(w, r)
	})
}

func (ctrl *OAuthController) authenticateUser(r *http.Request) (token string, err error) {
	err = r.ParseForm()
	//look for login/password in form data
	//but also allow basic auth, form data only works with POST requests
	login, password, ok := r.BasicAuth()
	if ok {
		r.Form.Add("login", login)
		r.Form.Add("password", password)
	}
	if err != nil {
		return "", fmt.Errorf("Error parsing form data %s", err.Error())
	}
	login = r.Form.Get("login")
	password = r.Form.Get("password")

	if login == "" && password == "" {
		return "", fmt.Errorf("Cannot authenticate user, form data missing.")
	}

	if login == "" || password == "" {
		return "", fmt.Errorf("Cannot authenticate user, login or password missing.")
	}
	//authenticate user against lndhub
	resp, err := http.PostForm(fmt.Sprintf("%s/auth", ctrl.Service.Config.LndHubUrl), r.Form)
	if err != nil {
		return "", fmt.Errorf("Error authenticating user %s", err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Cannot authenticate user, login or password wrong.")
	}
	//return access code
	tokenResponse := &TokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)
	if err != nil {
		return "", fmt.Errorf("Error authenticating user %s", err.Error())
	}
	return tokenResponse.AccessToken, nil
}

func (ctrl *OAuthController) PreRedirectErrorHandler(w http.ResponseWriter, r *server.AuthorizeRequest, err error) error {
	logrus.WithField("Authorize request", r).Error(err)
	sentry.CaptureException(err)
	return err
}

func (ctrl *OAuthController) AuthorizeScopeHandler(w http.ResponseWriter, r *http.Request) (scope string, err error) {
	requestedScope := r.FormValue("scope")
	if requestedScope == "" {
		return "", fmt.Errorf("Empty scope is not allowed")
	}
	for _, scope := range strings.Split(requestedScope, " ") {
		if _, found := ctrl.Service.Scopes[scope]; !found {
			err = fmt.Errorf("Scope not allowed: %s", scope)
			sentry.CaptureException(err)
			return "", err
		}
	}
	return requestedScope, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}
