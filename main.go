package main

import (
	"fmt"
	"net/http"
	"oauth2server/controllers"
	"oauth2server/service"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"

	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/gorilla/handlers"
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

	r := mux.NewRouter()
	r.HandleFunc("/oauth/authorize", controller.AuthorizationHandler)
	r.HandleFunc("/oauth/token", controller.TokenHandler)
	r.HandleFunc("/oauth/scopes", controller.ScopeHandler)

	//should not be publicly accesible
	r.HandleFunc("/admin/clients", controller.CreateClientHandler).Methods(http.MethodPost)
	r.HandleFunc("/admin/clients", controller.ListAllClientsHandler).Methods(http.MethodGet)
	r.HandleFunc("/admin/clients/{clientId}", controller.FetchClientHandler).Methods(http.MethodGet)
	r.HandleFunc("/admin/clients/{clientId}", controller.UpdateClientMetadataHandler).Methods(http.MethodPut)

	//manages connected apps for users
	subRouter := r.Methods(http.MethodGet, http.MethodPost, http.MethodDelete).Subrouter()
	subRouter.HandleFunc("/clients", controller.ListClientHandler).Methods(http.MethodGet)
	subRouter.HandleFunc("/clients/{clientId}", controller.UpdateClientHandler).Methods(http.MethodPost)
	subRouter.HandleFunc("/clients/{clientId}", controller.DeleteClientHandler).Methods(http.MethodDelete)
	subRouter.Use(controller.UserAuthorizeMiddleware)

	//Initialize API gateway
	gateways, err := svc.InitGateways()
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
