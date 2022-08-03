package service

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"oauth2server/constants"
	"oauth2server/models"
	"strconv"
	"time"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	"github.com/getsentry/sentry-go"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt"
	"github.com/koding/websocketproxy"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Service struct {
	OauthServer *server.Server
	Config      *Config
	ClientStore *oauth2gorm.ClientStore
	DB          *gorm.DB
	Scopes      map[string]string
}

func InitService(conf *Config) (svc *Service, err error) {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	clientStore, tokenStore, db, err := initStores(conf.DatabaseUri)
	if err != nil {
		logrus.Fatalf("Error connecting db: %s", err.Error())
	}
	manager.MapClientStorage(clientStore)
	manager.MapTokenStorage(tokenStore)

	manager.SetValidateURIHandler(CheckRedirectUriDomain)

	manager.SetAuthorizeCodeTokenCfg(&manage.Config{
		AccessTokenExp:    time.Duration(conf.AccessTokenExpSeconds) * time.Second,
		RefreshTokenExp:   time.Duration(conf.RefreshTokenExpSeconds) * time.Second,
		IsGenerateRefresh: true,
	})

	srv := server.NewServer(server.NewConfig(), manager)
	svc = &Service{
		DB:          db,
		OauthServer: srv,
		Config:      conf,
		ClientStore: clientStore,
	}
	return svc, nil
}

func initStores(dsn string) (clientStore *oauth2gorm.ClientStore, tokenStore *oauth2gorm.TokenStore, db *gorm.DB, err error) {
	//connect database
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, nil, nil, err
	}
	//migrated from legacy tables
	err = db.Table(constants.ClientTableName).AutoMigrate(&oauth2gorm.ClientStoreItem{})
	if err != nil {
		return nil, nil, nil, err
	}
	err = db.Table(constants.TokenTableName).AutoMigrate(&oauth2gorm.TokenStoreItem{})
	if err != nil {
		return nil, nil, nil, err
	}
	tokenStore = oauth2gorm.NewTokenStoreWithDB(&oauth2gorm.Config{TableName: constants.TokenTableName}, db, constants.GCIntervalSeconds)
	clientStore = oauth2gorm.NewClientStoreWithDB(&oauth2gorm.Config{TableName: constants.ClientTableName}, db)

	//initialize extra db tables
	err = db.AutoMigrate(&models.ClientMetaData{})
	if err != nil {
		return nil, nil, nil, err
	}

	logrus.Info("Succesfully connected to postgres database")
	return
}

func (svc *Service) InitGateways() (result []*OriginServer, err error) {
	targetBytes, err := ioutil.ReadFile(svc.Config.TargetFile)
	if err != nil {
		return nil, err
	}
	result = []*OriginServer{}
	err = json.Unmarshal(targetBytes, &result)
	if err != nil {
		return nil, err
	}
	svc.Scopes = map[string]string{}
	originHelperMap := map[string]http.Handler{}
	for _, origin := range result {
		origin.svc = svc
		svc.Scopes[origin.Scope] = origin.Description
		//avoid creating too much identical origin server objects
		//by storing them in a map
		value, found := originHelperMap[origin.Origin]
		if found {
			//use existing one
			origin.proxy = value
		} else {
			//create new one
			originUrl, err := url.Parse(origin.Origin)
			if err != nil {
				return nil, err
			}
			var proxy http.Handler
			if origin.IsWebsocket {
				prx := websocketproxy.NewProxy(originUrl)
				//allow all origins
				prx.Upgrader.CheckOrigin = func(r *http.Request) bool { return true }
				proxy = prx
			} else {
				proxy = httputil.NewSingleHostReverseProxy(originUrl)
			}
			originHelperMap[origin.Origin] = proxy
			origin.proxy = proxy
		}
	}
	return result, nil
}

func (svc *Service) InjectJWTAccessToken(token oauth2.TokenInfo, r *http.Request, isWebsocket bool) error {
	//mint and inject jwt token needed for origin server
	//the request is dispatched immediately, so the tokens can have a short expiry
	expirySeconds := 60
	lndhubId := token.GetUserID()
	lndhubToken, err := GenerateLNDHubAccessToken(svc.Config.JWTSecret, expirySeconds, lndhubId)
	if err != nil {
		return err
	}
	//inject lndhub token in query param if websocket
	//inject in header otherwise
	if isWebsocket {
		query := r.URL.Query()
		query.Set("token", lndhubToken)
		r.URL.RawQuery = query.Encode()
	}
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
	claims := &models.LNDhubClaims{
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
