package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"text/template"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	pg "github.com/vgarvardt/go-oauth2-pg/v4"
)

type OAuthController struct {
	oauthServer *server.Server
	service     *Service
}

type OriginServer struct {
	proxy            *httputil.ReverseProxy
	headerInjectFunc func(tokenInfo oauth2.TokenInfo, r *http.Request) error
}
type Service struct {
	Config      *Config
	clientStore *pg.ClientStore
	gateways    map[string]*OriginServer
}

var scopes = map[string][]string{
	"account:read":      {"/api/users/value4value", "Read your LN Address and value block information."},
	"invoices:create":   {"/ln/v2/invoices", "Create invoices on your behalf, fetch the status of a specific invoice."},
	"invoices:read":     {"/ln/v2/invoices/incoming", "Read your invoice history, get realtime updates on newly paid invoices."},
	"transactions:read": {"/ln/v2/invoices/outgoing", "Read your outgoing transaction history and check payment status."},
	"balance:read":      {"/ln/v2/balance", "Read your balance."},
}

func (ctrl *OAuthController) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	err := ctrl.oauthServer.HandleAuthorizeRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}
func (ctrl *OAuthController) TokenHandler(w http.ResponseWriter, r *http.Request) {
	err := ctrl.oauthServer.HandleTokenRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
func (ctrl *OAuthController) InternalErrorHandler(err error) (re *errors.Response) {
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
	token, login, err := ctrl.authenticateUser(r)
	if err != nil {
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
	//here be dragons
	//todo do this better, this is a hack
	//user id is stored as <ID>_<LOGIN>, in order to contain information that can be understood by both the rails app and lndhub
	return fmt.Sprintf("%.0f_%s", claims["id"].(float64), login), nil
}

func (ctrl *OAuthController) authenticateUser(r *http.Request) (token, login string, err error) {
	//look for login/password in form data
	err = r.ParseForm()
	if err != nil {
		return "", "", fmt.Errorf("Error parsing form data %s", err.Error())
	}
	login = r.Form.Get("login")
	password := r.Form.Get("password")

	if login == "" || password == "" {
		return "", "", fmt.Errorf("Cannot authenticate user, login or password missing.")
	}
	//authenticate user against lndhub
	resp, err := http.PostForm(fmt.Sprintf("%s/auth", ctrl.service.Config.LndHubUrl), r.Form)
	if err != nil {
		return "", "", fmt.Errorf("Error authenticating user %s", err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("Cannot authenticate user, login or password wrong.")
	}
	//return access code
	tokenResponse := &TokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)
	if err != nil {
		return "", "", fmt.Errorf("Error authenticating user %s", err.Error())
	}
	return tokenResponse.AccessToken, login, nil
}

func (ctrl *OAuthController) ClientHandler(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodPost:
		ctrl.CreateClientHandler(w, r)
		return
	default:
		_, err := w.Write([]byte("Method not supported"))
		if err != nil {
			logrus.Error(err)
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
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
		if _, found := scopes[scope]; !found {
			return "", fmt.Errorf("Scope not allowed: %s", scope)
		}
	}
	return requestedScope, nil
}
func (ctrl *OAuthController) DemoAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	clientId := r.URL.Query().Get("client_id")
	redirectUrl := r.URL.Query().Get("redirect_url")
	requestedScopes := r.URL.Query().Get("scope")
	scopeList := strings.Split(requestedScopes, " ")
	scopeDescriptions := []string{}
	for _, sc := range scopeList {
		scopeDescriptions = append(scopeDescriptions, scopes[sc][1])
	}
	tmpl := template.Must(template.ParseFiles("static/auth.html"))

	data := AuthorizePageData{
		Scopes:      scopeDescriptions,
		ClientName:  clientId,
		RedirectUrl: redirectUrl,
		Scope:       requestedScopes,
	}
	err := tmpl.Execute(w, data)
	if err != nil {
		logrus.Error(err)
	}
}

type AuthorizePageData struct {
	Scopes      []string
	ClientName  string
	RedirectUrl string
	Scope       string
}
type TokenResponse struct {
	AccessToken string `json:"access_token"`
}
