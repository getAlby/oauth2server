package main

import (
	"fmt"
	"net/http"
	"oauth2server/internal/clients"
	"oauth2server/internal/repository"
	"oauth2server/internal/tokens"
	"oauth2server/middleware"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	muxtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"

	"github.com/getsentry/sentry-go"
)

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	// Load env file as env variables
	err := godotenv.Load(".env")
	if err != nil {
		logrus.Errorf("Error loading environment variables: %v", err)
	}
	//load global config
	sentryDsn := os.Getenv("SENTRY_DSN")
	ddAgentUrl := os.Getenv("DATADOG_AGENT_URL")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	// Setup exception tracking with Sentry if configured
	if sentryDsn != "" {
		if err = sentry.Init(sentry.ClientOptions{
			Dsn:          sentryDsn,
			IgnoreErrors: []string{"401"},
		}); err != nil {
			logrus.Errorf("sentry init error: %v", err)
		}
		defer sentry.Flush(2 * time.Second)
	}

	r := muxtrace.NewRouter(muxtrace.WithServiceName("oauth2server"))
	if ddAgentUrl != "" {
		tracer.Start(tracer.WithAgentAddr(ddAgentUrl))
		defer tracer.Stop()
	}

	//todo: init scopes
	scopes := map[string]string{}

	//set up PG repositories
	cs, ts, db, err := repository.InitPGStores()
	if err != nil {
		logrus.Fatal(err)
	}

	oauthRouter := r.NewRoute().Subrouter()

	//set up token service
	//responsible for managing oauth tokens
	//this service handles the oauth authorization
	tokenSvc, err := tokens.NewService(cs, ts, scopes)
	if err != nil {
		logrus.Fatal(err)
	}
	oauthRouter.Use(
		handlers.RecoveryHandler(),
		func(h http.Handler) http.Handler { return middleware.LoggingMiddleware(h) },
	)

	//create client management service
	//responsible for managing oauth clients
	//there are admin routes to manage all clients
	//and user routes to manage clients created by the currently authenticated user
	userControlledRouter := r.Methods(http.MethodGet, http.MethodPost, http.MethodDelete).Subrouter()
	clientStore := clients.NewGormClientStore(db, cs)
	clientSvc := clients.NewService(clientStore, scopes)
	clients.RegisterRoutes(oauthRouter, userControlledRouter, clientSvc)

	userControlledRouter.Use(tokenSvc.UserAuthorizeMiddleware)
	userControlledRouter.Use(handlers.RecoveryHandler(),
		func(h http.Handler) http.Handler { return middleware.LoggingMiddleware(h) },
	)

	//Initialize API gateway
	//todo: move to package
	gateways, err := svc.InitGateways()
	if err != nil {
		logrus.Fatal(err)
	}

	for _, gw := range gateways {
		r.NewRoute().Path(gw.MatchRoute).Methods(gw.Method).Handler(middleware.RegisterMiddleware(gw, conf))
	}

	logrus.Infof("Server starting on port %s", port)
	logrus.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), r))
}
