package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/gorilla/handlers"
)

const (
	gcIntervalSeconds = 60
	clientTableName   = "oauth2_clients"
	tokenTableName    = "oauth2_tokens"
)

func main() {
	// Load env file as env variables
	err := godotenv.Load(".env")
	if err != nil {
		logrus.Errorf("Error loading environment variables: %v", err)
	}
	// Load in config from env vars
	conf := &Config{}
	err = envconfig.Process("", conf)
	if err != nil {
		logrus.Fatalf("Error loading environment variables: %v", err)
	}
	logrus.SetReportCaller(true)

	// Setup exception tracking with Sentry if configured
	if conf.SentryDSN != "" {
		if err = sentry.Init(sentry.ClientOptions{
			Dsn:          conf.SentryDSN,
			IgnoreErrors: []string{"401"},
		}); err != nil {
			logrus.Errorf("sentry init error: %v", err)
		}
		defer sentry.Flush(2 * time.Second)
	}

	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	clientStore, tokenStore, db, err := initStores(conf.DatabaseUri)
	if err != nil {
		logrus.Fatalf("Error connecting db: %s", err.Error())
	}
	err = MigrateTokenData(db)
	if err != nil {
		logrus.Fatalf("Error migrating db: %s", err.Error())
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
	svc := &Service{
		db:          db,
		oauthServer: srv,
		Config:      conf,
		clientStore: clientStore,
	}
	controller := &OAuthController{
		service: svc,
	}
	srv.SetUserAuthorizationHandler(controller.UserAuthorizeHandler)
	srv.SetInternalErrorHandler(controller.InternalErrorHandler)
	srv.SetAuthorizeScopeHandler(controller.AuthorizeScopeHandler)

	r := mux.NewRouter()
	r.HandleFunc("/oauth/authorize", controller.AuthorizationHandler)
	r.HandleFunc("/oauth/token", controller.TokenHandler)
	r.HandleFunc("/oauth/scopes", controller.ScopeHandler)

	//should not be publicly accesible
	r.HandleFunc("/admin/clients", controller.CreateClientHandler).Methods(http.MethodPost)

	//Initialize API gateway
	gateways, err := svc.initGateways()
	if err != nil {
		logrus.Fatal(err)
	}
	for _, gw := range gateways {
		r.Handle(gw.MatchRoute, gw)
	}

	logrus.Infof("Server starting on port %d", conf.Port)
	logrus.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", conf.Port), registerMiddleware(r)))
}

//panic recover, logging, Sentry middlewares
func registerMiddleware(in http.Handler) http.Handler {
	recoveryHandler := handlers.RecoveryHandler()(in)
	loggingHandler := handlers.CombinedLoggingHandler(os.Stdout, recoveryHandler)
	result := sentryhttp.New(sentryhttp.Options{}).Handle(loggingHandler)
	return result
}

func (svc *Service) initGateways() (result []*OriginServer, err error) {
	targetBytes, err := ioutil.ReadFile(svc.Config.TargetFile)
	if err != nil {
		return nil, err
	}
	result = []*OriginServer{}
	err = json.Unmarshal(targetBytes, &result)
	if err != nil {
		return nil, err
	}
	svc.scopes = map[string]string{}
	originHelperMap := map[string]*httputil.ReverseProxy{}
	for _, origin := range result {
		origin.svc = svc
		svc.scopes[origin.Scope] = origin.Description
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

func initStores(dsn string) (clientStore *oauth2gorm.ClientStore, tokenStore *oauth2gorm.TokenStore, db *gorm.DB, err error) {
	//connect database
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, nil, nil, err
	}
	//migrated from legacy tables
	err = db.Table(clientTableName).AutoMigrate(&oauth2gorm.ClientStoreItem{})
	if err != nil {
		return nil, nil, nil, err
	}
	err = db.Table(tokenTableName).AutoMigrate(&oauth2gorm.TokenStoreItem{})
	if err != nil {
		return nil, nil, nil, err
	}
	tokenStore = oauth2gorm.NewTokenStoreWithDB(&oauth2gorm.Config{TableName: tokenTableName}, db, gcIntervalSeconds)
	clientStore = oauth2gorm.NewClientStoreWithDB(&oauth2gorm.Config{TableName: clientTableName}, db)

	logrus.Info("Succesfully connected to postgres database")
	return
}
