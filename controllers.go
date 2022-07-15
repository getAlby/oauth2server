package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	pg "github.com/vgarvardt/go-oauth2-pg/v4"
)

type OAuthController struct {
	service *Service
}

type Service struct {
	oauthServer *server.Server
	Config      *Config
	clientStore *pg.ClientStore
	scopes      map[string]string
}

func (ctrl *OAuthController) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	err := ctrl.service.oauthServer.HandleAuthorizeRequest(w, r)
	if err != nil {
		sentry.CaptureException(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (ctrl *OAuthController) ScopeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-type", "application/json")
	err := json.NewEncoder(w).Encode(ctrl.service.scopes)
	if err != nil {
		logrus.Error(err)
	}
}

func (ctrl *OAuthController) TokenHandler(w http.ResponseWriter, r *http.Request) {
	err := ctrl.service.oauthServer.HandleTokenRequest(w, r)
	if err != nil {
		sentry.CaptureException(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func (ctrl *OAuthController) InternalErrorHandler(err error) (re *errors.Response) {
	sentry.CaptureException(err)
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
		sentry.CaptureException(err)
		return "", err
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return ctrl.service.Config.JWTSecret, nil
	})
	if err != nil {
		return "", err
	}
	if claims["id"] == nil {
		return "", fmt.Errorf("Cannot authenticate user, token does not contain user id")
	}
	return fmt.Sprintf("%.0f", claims["id"].(float64)), nil
}

func (ctrl *OAuthController) authenticateUser(r *http.Request) (token string, err error) {
	//look for login/password in form data
	err = r.ParseForm()
	if err != nil {
		return "", fmt.Errorf("Error parsing form data %s", err.Error())
	}
	login := r.Form.Get("login")
	password := r.Form.Get("password")

	if login == "" || password == "" {
		return "", fmt.Errorf("Cannot authenticate user, login or password missing.")
	}
	//authenticate user against lndhub
	resp, err := http.PostForm(fmt.Sprintf("%s/auth", ctrl.service.Config.LndHubUrl), r.Form)
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
func (ctrl *OAuthController) CreateClientHandler(w http.ResponseWriter, r *http.Request) {
	clientInfo := &models.Client{}
	err := json.NewDecoder(r.Body).Decode(clientInfo)
	if err != nil {
		logrus.Errorf("Error decoding client info request %s", err.Error())
		_, err = w.Write([]byte("Could not parse create client request"))
		if err != nil {
			logrus.Error(err)
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = ctrl.service.clientStore.Create(clientInfo)
	if err != nil {
		logrus.Errorf("Error storing client info %s", err.Error())
		_, err = w.Write([]byte("Something went wrong while storing client info"))
		if err != nil {
			logrus.Error(err)
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-type", "application/json")
	err = json.NewEncoder(w).Encode(clientInfo)
	if err != nil {
		logrus.Error(err)
	}
}

func (ctrl *OAuthController) AuthorizeScopeHandler(w http.ResponseWriter, r *http.Request) (scope string, err error) {
	requestedScope := r.FormValue("scope")
	if requestedScope == "" {
		return "", fmt.Errorf("Empty scope is not allowed")
	}
	for _, scope := range strings.Split(requestedScope, " ") {
		if _, found := ctrl.service.scopes[scope]; !found {
			err = fmt.Errorf("Scope not allowed: %s", scope)
			sentry.CaptureException(err)
			return "", err
		}
	}
	return requestedScope, nil
}
func CheckRedirectUriDomain(baseURI, redirectURI string) error {
	parsedClientUri, err := url.Parse(baseURI)
	if err != nil {
		return err
	}
	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil {
		return err
	}
	if parsedClientUri.Host != parsedRedirect.Host || parsedClientUri.Scheme != parsedRedirect.Scheme {
		err = fmt.Errorf("Wrong redirect uri for client. redirect_uri %s, client domain %s", baseURI, redirectURI)
		sentry.CaptureException(err)
		return err
	}
	return nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}
