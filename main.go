package main

import (
	"fmt"
	"net/http"
	"oauth2server/controllers"
	"oauth2server/middleware"
	"oauth2server/service"
	"time"

	"github.com/gorilla/handlers"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	muxtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/gorilla/mux"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"

	"github.com/getsentry/sentry-go"
)

func main() {
	// Load env file as env variables
	err := godotenv.Load(".env")
	if err != nil {
		logrus.Errorf("Error loading environment variables: %v", err)
	}
	// Load in config from env vars
	conf := &service.Config{}
	err = envconfig.Process("", conf)
	if err != nil {
		logrus.Fatalf("Error loading environment variables: %v", err)
	}
	logrus.SetFormatter(&logrus.JSONFormatter{})

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

	svc, err := service.InitService(conf)
	if err != nil {
		logrus.Fatalf("Error initializing service: %s", err.Error())
	}
	controller := &controllers.OAuthController{
		Service: svc,
	}
	svc.OauthServer.SetUserAuthorizationHandler(controller.UserAuthorizeHandler)
	svc.OauthServer.SetInternalErrorHandler(controller.InternalErrorHandler)
	svc.OauthServer.SetAuthorizeScopeHandler(controller.AuthorizeScopeHandler)
	svc.OauthServer.SetPreRedirectErrorHandler(controller.PreRedirectErrorHandler)

	r := muxtrace.NewRouter(muxtrace.WithServiceName("oauth2server"))
	if conf.DatadogAgentUrl != "" {
		tracer.Start(tracer.WithAgentAddr(conf.DatadogAgentUrl))
		defer tracer.Stop()
	}

	oauthRouter := r.NewRoute().Subrouter()
	oauthRouter.HandleFunc("/oauth/authorize", controller.AuthorizationHandler)
	oauthRouter.HandleFunc("/oauth/token", controller.TokenHandler)
	oauthRouter.HandleFunc("/oauth/scopes", controller.ScopeHandler)
	oauthRouter.HandleFunc("/oauth/endpoints", controller.EndpointHandler)

	oauthRouter.HandleFunc("/oauth/token/introspect", controller.TokenIntrospectHandler).Methods(http.MethodGet)

	//these routes should not be publicly accesible
	oauthRouter.HandleFunc("/admin/clients", controller.CreateClientHandler).Methods(http.MethodPost)
	oauthRouter.HandleFunc("/admin/clients", controller.ListAllClientsHandler).Methods(http.MethodGet)
	oauthRouter.HandleFunc("/admin/clients/{clientId}", controller.FetchClientHandler).Methods(http.MethodGet)
	oauthRouter.HandleFunc("/admin/clients/{clientId}", controller.UpdateClientMetadataHandler).Methods(http.MethodPut)
	oauthRouter.Use(
		handlers.RecoveryHandler(),
		func(h http.Handler) http.Handler { return middleware.LoggingMiddleware(h) },
	)

	//manages connected apps for users
	userControlledRouter := r.Methods(http.MethodGet, http.MethodPost, http.MethodDelete).Subrouter()
	userControlledRouter.HandleFunc("/clients", controller.ListClientHandler).Methods(http.MethodGet)
	userControlledRouter.HandleFunc("/clients/{clientId}", controller.UpdateClientHandler).Methods(http.MethodPost)
	userControlledRouter.HandleFunc("/clients/{clientId}", controller.DeleteClientHandler).Methods(http.MethodDelete)
	userControlledRouter.Use(controller.UserAuthorizeMiddleware)
	userControlledRouter.Use(handlers.RecoveryHandler(),
		func(h http.Handler) http.Handler { return middleware.LoggingMiddleware(h) },
	)

	//Initialize API gateway
	gateways, err := svc.InitGateways()
	if err != nil {
		logrus.Fatal(err)
	}

	for _, gw := range gateways {
		r.Handle(gw.MatchRoute, middleware.RegisterMiddleware(gw, conf))
	}

	logrus.Infof("Server starting on port %d", conf.Port)
	logrus.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", conf.Port), r))
}
