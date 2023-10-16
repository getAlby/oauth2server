package main

import (
	"fmt"
	"net/http"
	"oauth2server/internal/clients"
	"oauth2server/internal/gateway"
	"oauth2server/internal/middleware"
	"oauth2server/internal/tokens"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	// Load env file as env variables
	err := godotenv.Load(".env")
	if err != nil {
		logrus.Errorf("Error loading environment variables: %v", err)
	}
	//load global config
	type config struct {
		Port       int    `default:"8081"`
		LndHubUrl  string `envconfig:"LNDHUB_URL" required:"true"`
		JWTSecret  []byte `envconfig:"JWT_SECRET" required:"true"`
		TargetFile string `envconfig:"TARGET_FILE" default:"targets.json"`
	}
	globalConf := &config{}
	err = envconfig.Process("", globalConf)
	if err != nil {
		logrus.Fatal(err)
	}

	r := mux.NewRouter()
	//todo: init scopes
	scopes := map[string]string{}

	oauthRouter := r.NewRoute().Subrouter()

	//create auth middleware
	//todo: run a different middleware with hard-coded credentials
	lndhubUserAuth, err := middleware.NewLNDHubUserAuth(globalConf.JWTSecret, globalConf.LndHubUrl)
	if err != nil {
		logrus.Fatal(err)
	}
	//set up in-memory stores
	cs := clients.NewInMem()
	ts := tokens.NewInmemStore()
	tokenSvc, err := tokens.NewService(cs, ts, scopes, lndhubUserAuth.LNDHubUserAuth)
	if err != nil {
		logrus.Fatal(err)
	}
	tokens.RegisterRoutes(oauthRouter, tokenSvc)
	oauthRouter.Use(
		handlers.RecoveryHandler(),
		func(h http.Handler) http.Handler { return middleware.LoggingMiddleware(h) },
	)

	//create client management service
	//responsible for managing oauth clients
	//there are admin routes to manage all clients
	//and user routes to manage clients created by the currently authenticated user
	userControlledRouter := r.Methods(http.MethodGet, http.MethodPost, http.MethodDelete).Subrouter()
	clientSvc := clients.NewService(cs, scopes)
	clients.RegisterRoutes(oauthRouter, userControlledRouter, clientSvc)

	userControlledRouter.Use(lndhubUserAuth.UserAuthorizeMiddleware)
	userControlledRouter.Use(handlers.RecoveryHandler(),
		func(h http.Handler) http.Handler { return middleware.LoggingMiddleware(h) },
	)

	//Initialize API gateway
	gateways, err := gateway.InitGateways(
		globalConf.TargetFile,
		tokenSvc.OauthServer.Manager.LoadAccessToken,
		globalConf.JWTSecret)
	if err != nil {
		logrus.Fatal(err)
	}

	for _, gw := range gateways {
		r.NewRoute().Path(gw.MatchRoute).Methods(gw.Method).Handler(middleware.RegisterMiddleware(gw))
	}

	logrus.Infof("Server starting on port %d", globalConf.Port)
	logrus.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", globalConf.Port), r))
}
