package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
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
}

type ScopedClaims struct {
	jwt.StandardClaims
	Scope string `json:"scope"`
}

var scopes = map[string]string{
	"invoices:create":           "Create invoices on your behalf.",
	"invoices:read":             "Read your invoice history, get realtime updates on newly paid invoices.",
	"invoices:keysend:create":   "Fetch information needed for receiving value4value donations (pubkey, customKey/customValue).",
	"invoices:keysend:read":     "Read your incoming keysend payments and boostagrams.",
	"transactions:read":         "Read your outgoing transaction history and check payment status.",
	"transactions:keysend:read": "Read your outgoing keysend payments and boostagrams.",
	"balance:read":              "Read your balance.",
}

//Token function mints scoped tokens using JWT_SECRET
func (svc *Service) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	claims := &ScopedClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  data.Client.GetID(),
			Subject:   data.UserID,
			ExpiresAt: data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
		},
		Scope: data.TokenInfo.GetScope(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	access, err = token.SignedString(svc.Config.JWTSecret)
	if err != nil {
		return "", "", err
	}
	if isGenRefresh {
		t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}
	return access, refresh, nil
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
	if claims["scope"] != nil {
		return "", fmt.Errorf("Cannot authenticate user, token not authorized for generating new tokens")
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
