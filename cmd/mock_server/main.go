package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"oauth2server/internal/clients"
	"oauth2server/internal/gateway"
	"oauth2server/internal/middleware"
	"oauth2server/internal/tokens"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.Info("starting mock server. ONLY FOR DEVELOPMENT!")
	// Load env file as env variables
	err := godotenv.Load(".env")
	if err != nil {
		logrus.Errorf("Error loading environment variables: %v", err)
	}
	//load global config
	type config struct {
		Port           int    `default:"8081"`
		MockServerPort int    `default:"3000"`
		JWTSecret      []byte `envconfig:"JWT_SECRET" required:"true"`
		TargetFile     string `envconfig:"TARGET_FILE" default:"targets.json"`
	}
	globalConf := &config{}
	err = envconfig.Process("", globalConf)
	if err != nil {
		logrus.Fatal(err)
	}

	r := mux.NewRouter()
	scopes, err := tokens.LoadScopes(globalConf.TargetFile)
	if err != nil {
		logrus.Fatal(err)
	}

	oauthRouter := r.NewRoute().Subrouter()

	//here we can use the same jwt middleware
	//we simply mint & log a JWT token the developer
	//can use to make authorization requests
	auth, err := middleware.NewJWTAuth(globalConf.JWTSecret)
	if err != nil {
		logrus.Fatal(err)
	}
	testUserId := int64(12345)
	testJwt, err := middleware.GenerateJWT(globalConf.JWTSecret, middleware.Claims{ID: &testUserId})
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("Mock auth: use the following JWT token to make authorization requests: %s", testJwt)
	//set up in-memory stores
	cs := clients.NewInMem()
	ts := tokens.NewInmemStore()
	tokenSvc, err := tokens.NewService(cs, ts, scopes, auth.JWTAuth)
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

	//create client id / secret
	logrus.Info("creating test client with id 'id', secret 'secret' and redirect uri 'http://localhost:8080'")
	cs.Create(context.Background(), "id", "secret", "http://localhost:8080", "http://example.com", "http://example.com/image", "example client")

	//create token for this client
	authCode, err := tokenSvc.OauthServer.Manager.GenerateAuthToken(context.Background(), oauth2.Code, &oauth2.TokenGenerateRequest{
		ClientID:     "id",
		ClientSecret: "secret",
		UserID:       fmt.Sprintf("%d", testUserId),
		RedirectURI:  "http://localhost:8080",
		Scope:        "balance:read",
	})
	if err != nil {
		logrus.WithError(err).Fatal("could not generate code")
	}
	access, err := tokenSvc.OauthServer.Manager.GenerateAccessToken(context.Background(), oauth2.AuthorizationCode, &oauth2.TokenGenerateRequest{
		Code:         authCode.GetCode(),
		ClientID:     "id",
		ClientSecret: "secret",
		UserID:       "12345",
		RedirectURI:  "http://localhost:8080",
		Scope:        "balance:read",
	})
	if err != nil {
		logrus.WithError(err).Fatal("could not generate token")
	}
	logrus.WithField("token", access).Info("generated test access token")

	userControlledRouter.Use(auth.UserAuthorizeMiddleware)
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

	//start mock server that will respond some data and the JWT token
	//we might parse the JWT token and return the user id for better testing later
	//you can add anything you like here
	downstream := mux.NewRouter()
	downstream.HandleFunc("/balance", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"authorization header": r.Header.Get("Authorization"),
			"message":              "you've reached the downstream mocker server, well done.",
		})
	})
	go func() {
		http.ListenAndServe(fmt.Sprintf(":%d", globalConf.MockServerPort), downstream)
	}()

	logrus.Infof("Server starting on port %d", globalConf.Port)
	logrus.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", globalConf.Port), r))
}
