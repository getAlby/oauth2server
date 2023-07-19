package main

import (
	"fmt"
	"net/http"
	"oauth2server/controllers"
	"oauth2server/service"
	"strings"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"

	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
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

	r := mux.NewRouter()

	oauthRouter := r.NewRoute().Subrouter()
	oauthRouter.HandleFunc("/oauth/authorize", controller.AuthorizationHandler)
	oauthRouter.HandleFunc("/oauth/token", controller.TokenHandler)
	oauthRouter.HandleFunc("/oauth/scopes", controller.ScopeHandler)
	oauthRouter.HandleFunc("/oauth/endpoints", controller.EndpointHandler)

	//these routes should not be publicly accesible
	oauthRouter.HandleFunc("/admin/clients", controller.CreateClientHandler).Methods(http.MethodPost)
	oauthRouter.HandleFunc("/admin/clients", controller.ListAllClientsHandler).Methods(http.MethodGet)
	oauthRouter.HandleFunc("/admin/clients/{clientId}", controller.FetchClientHandler).Methods(http.MethodGet)
	oauthRouter.HandleFunc("/admin/clients/{clientId}", controller.UpdateClientMetadataHandler).Methods(http.MethodPut)
	oauthRouter.Use(
		handlers.RecoveryHandler(),
		func(h http.Handler) http.Handler { return loggingMiddleware(h) },
	)

	//manages connected apps for users
	userControlledRouter := r.Methods(http.MethodGet, http.MethodPost, http.MethodDelete).Subrouter()
	userControlledRouter.HandleFunc("/clients", controller.ListClientHandler).Methods(http.MethodGet)
	userControlledRouter.HandleFunc("/clients/{clientId}", controller.UpdateClientHandler).Methods(http.MethodPost)
	userControlledRouter.HandleFunc("/clients/{clientId}", controller.DeleteClientHandler).Methods(http.MethodDelete)
	userControlledRouter.Use(controller.UserAuthorizeMiddleware)
	userControlledRouter.Use(handlers.RecoveryHandler(),
		func(h http.Handler) http.Handler { return loggingMiddleware(h) },
	)

	//Initialize API gateway
	gateways, err := svc.InitGateways()
	if err != nil {
		logrus.Fatal(err)
	}

	for _, gw := range gateways {
		r.Handle(gw.MatchRoute, registerMiddleware(gw, conf))
	}

	logrus.Infof("Server starting on port %d", conf.Port)
	logrus.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", conf.Port), r))
}

// panic recover, logging, Sentry middlewares
func registerMiddleware(h http.Handler, conf *service.Config) http.Handler {
	h = handlers.RecoveryHandler()(h)
	h = loggingMiddleware(h)
	h = sentryhttp.New(sentryhttp.Options{}).Handle(h)
	return h
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		entry := logrus.NewEntry(logrus.StandardLogger())
		entry = entry.WithField("host", r.Host)
		entry = entry.WithField("id", r.Header.Get("X-Request-Id"))
		remoteIpList := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if len(remoteIpList) > 0 {
			entry = entry.WithField("remote_ip", remoteIpList[0])
		}
		entry = entry.WithField("referer", r.Referer())
		entry = entry.WithField("user_agent", r.UserAgent())
		entry = entry.WithField("uri", r.URL.Path)
		//this already calls next.ServeHttp
		m := httpsnoop.CaptureMetrics(next, w, r)
		entry = entry.WithField("latency", m.Duration.Seconds())
		entry = entry.WithField("status", m.Code)
		entry = entry.WithField("bytes_out", m.Written)
		entry.Info()
	})
}
