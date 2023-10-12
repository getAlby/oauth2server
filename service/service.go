package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"oauth2server/constants"
	"oauth2server/internal/clients"
	"oauth2server/models"
	"strconv"
	"time"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	"github.com/getsentry/sentry-go"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/jackc/pgx/v5/stdlib"
	sqltrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/database/sql"
	gormtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorm.io/gorm.v1"
)

type Service struct {
	OauthServer *server.Server
	Endpoints   []*OriginServer
	Config      *Config
	ClientStore *oauth2gorm.ClientStore
	DB          *gorm.DB
	Scopes      map[string]string
}

func CombinedClientInfoHandler(r *http.Request) (clientID, clientSecret string, err error) {
	clientID, clientSecret, err = server.ClientBasicHandler(r)
	if err != nil {
		return server.ClientFormHandler(r)
	}
	return
}

func (svc *Service) AccessTokenExpHandler(w http.ResponseWriter, r *http.Request) (exp time.Duration, err error) {
	expiry := r.FormValue("expires_in")
	if expiry != "" {
		expiresIn, err := strconv.Atoi(expiry)
		if err != nil {
			return time.Duration(0), err
		}
		return time.Duration(expiresIn) * time.Second, nil
	}
	return time.Duration(svc.Config.AccessTokenExpSeconds) * time.Second, nil
}

func InitService(conf *Config) (svc *Service, err error) {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	clientStore, tokenStore, db, err := initStores(conf.DatabaseUri, conf)
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

	//use the default refresh config but add the reset refresh time = true
	//otherwise refreshing will always break after the token birthday + refresh token exiry
	manager.SetRefreshTokenCfg(
		&manage.RefreshingConfig{
			IsGenerateRefresh:  true,
			IsRemoveAccess:     true,
			IsRemoveRefreshing: true,
			IsResetRefreshTime: true,
		})

	srv := server.NewServer(server.NewConfig(), manager)
	srv.ClientInfoHandler = CombinedClientInfoHandler
	svc = &Service{
		DB:          db,
		OauthServer: srv,
		Config:      conf,
		ClientStore: clientStore,
	}
	srv.AccessTokenExpHandler = svc.AccessTokenExpHandler
	return svc, nil
}

func initStores(dsn string, cfg *Config) (clientStore *oauth2gorm.ClientStore, tokenStore *oauth2gorm.TokenStore, db *gorm.DB, err error) {
	//connect database
	var sqlDb *sql.DB
	if cfg.DatadogAgentUrl != "" {
		sqltrace.Register("pgx", &stdlib.Driver{}, sqltrace.WithServiceName("oauth2server"))
		sqlDb, err = sqltrace.Open("pgx", dsn)
		if err != nil {
			return nil, nil, nil, err
		}
		db, err = gormtrace.Open(postgres.New(postgres.Config{Conn: sqlDb}), &gorm.Config{})
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			return nil, nil, nil, err
		}

		sqlDb, err = db.DB()
		if err != nil {
			return nil, nil, nil, err
		}
	}

	sqlDb.SetMaxOpenConns(cfg.DatabaseMaxConns)
	sqlDb.SetMaxIdleConns(cfg.DatabaseMaxIdleConns)
	sqlDb.SetConnMaxLifetime(time.Duration(cfg.DatabaseConnMaxLifetime) * time.Second)

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
	err = db.AutoMigrate(&clients.ClientMetaData{})
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
	svc.Endpoints = result
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
			proxy := httputil.NewSingleHostReverseProxy(originUrl)
			originHelperMap[origin.Origin] = proxy
			origin.proxy = proxy
		}
	}
	return result, nil
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
		err = fmt.Errorf("Wrong Redirect URI. Provided: [ Scheme: %s, Host: %s ], Expected: [ Scheme: %s, Host: %s ]", parsedRedirect.Scheme, parsedRedirect.Host, parsedClientUri.Scheme, parsedClientUri.Host)
		sentry.CaptureException(err)
		return err
	}
	return nil
}
