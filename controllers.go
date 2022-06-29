package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"

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

type Service struct {
	Config      *Config
	clientStore *pg.ClientStore
	gateways    map[string]*httputil.ReverseProxy
}

var scopes = map[string][]string{
	"invoices:create":   {"/v2/invoices", "Create invoices on your behalf."},
	"invoices:read":     {"/v2/invoices/incoming", "Read your invoice history, get realtime updates on newly paid invoices."},
	"transactions:read": {"/v2/invoices/outgoing", "Read your outgoing transaction history and check payment status."},
	"balance:read":      {"/v2/balance", "Read your balance."},
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
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return ctrl.service.Config.JWTSecret, nil
	})
	if err != nil {
		return "", err
	}
	//todo change to sub, which should have string type
	if claims["id"] == nil {
		return "", fmt.Errorf("Cannot authenticate user, token does not contain user id")
	}
	return fmt.Sprintf("%.0f", claims["id"].(float64)), nil
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
	requestedScope := r.URL.Query().Get("scope")
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
