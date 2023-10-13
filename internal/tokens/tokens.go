package tokens

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"oauth2server/models"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	oauthErrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

var CONTEXT_ID_KEY string = "ID"

type service struct {
	oauthServer *server.Server
	scopes      map[string]string
	config      Config
}

func RegisterRoutes(r *mux.Router, svc *service) {
	r.HandleFunc("/oauth/authorize", svc.AuthorizationHandler)
	r.HandleFunc("/oauth/token", svc.TokenHandler)
	r.HandleFunc("/oauth/scopes", svc.ScopeHandler)
	r.HandleFunc("/oauth/token/introspect", svc.TokenIntrospectHandler).Methods(http.MethodGet)
}

func NewService(cs oauth2.ClientStore, ts oauth2.TokenStore, scopes map[string]string) (result *service, err error) {
	//create oauth server from conf
	conf := Config{}
	err = envconfig.Process("", &conf)
	if err != nil {
		return nil, err
	}
	srv, err := initOauthServer(conf, cs, ts)
	if err != nil {
		return nil, err
	}
	svc := &service{
		oauthServer: srv,
		scopes:      scopes,
	}
	srv.SetUserAuthorizationHandler(svc.UserAuthorizeHandler)
	srv.SetInternalErrorHandler(svc.InternalErrorHandler)
	srv.SetAuthorizeScopeHandler(svc.AuthorizeScopeHandler)
	srv.SetPreRedirectErrorHandler(preRedirectErrorHandler)

	return svc, nil
}

func (svc *service) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	err := svc.oauthServer.HandleAuthorizeRequest(w, r)
	if err != nil {
		sentry.CaptureException(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (svc *service) TokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	gt, tgr, err := svc.oauthServer.ValidationTokenRequest(r)
	if err != nil {
		sentry.CaptureException(err)
		svc.tokenError(w, err)
		return
	}

	ti, err := svc.oauthServer.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		sentry.CaptureException(err)
		svc.tokenError(w, err)
		return
	}

	svc.token(w, svc.oauthServer.GetTokenData(ti), nil)
}

func (svc *service) TokenIntrospectHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenInfo, err := svc.oauthServer.Manager.LoadAccessToken(r.Context(), token)
	if err != nil {
		svc.tokenError(w, err)
		return
	}
	// for middleware
	lti := r.Context().Value("token_info")
	if lti != nil {
		logTokenInfo := lti.(*models.LogTokenInfo)
		logTokenInfo.UserId = tokenInfo.GetUserID()
		logTokenInfo.ClientId = tokenInfo.GetClientID()
	}
	info := map[string]interface{}{
		"client_id":    tokenInfo.GetClientID(),
		"redirect_uri": tokenInfo.GetRedirectURI(),
		"scopes":       map[string]string{},
	}
	scopes := info["scopes"].(map[string]string)
	w.Header().Add("Content-type", "application/json")
	for _, sc := range strings.Split(tokenInfo.GetScope(), " ") {
		scopes[sc] = svc.scopes[sc]
	}
	err = json.NewEncoder(w).Encode(info)
	if err != nil {
		logrus.Error(err)
	}
}

func (svc *service) ScopeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-type", "application/json")
	err := json.NewEncoder(w).Encode(svc.scopes)
	if err != nil {
		logrus.Error(err)
	}
}

func (svc *service) tokenError(w http.ResponseWriter, err error) error {
	data, statusCode, header := svc.oauthServer.GetErrorData(err)
	logrus.
		WithField("error_description", data["error_description"]).
		WithField("error", err).
		Error("token error")
	return svc.token(w, data, header, statusCode)
}

func (svc *service) token(w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) error {
	if fn := svc.oauthServer.ResponseTokenHandler; fn != nil {
		return fn(w, data, header, statusCode...)
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	for key := range header {
		w.Header().Set(key, header.Get(key))
	}

	status := http.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}

	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

func (svc *service) InternalErrorHandler(err error) (re *errors.Response) {
	//workaround to not show "sql: no rows in result set" to user
	sentry.CaptureException(err)
	description := oauthErrors.Descriptions[err]
	statusCode := oauthErrors.StatusCodes[err]
	if description != "" && statusCode != 0 {
		return &errors.Response{
			Error:       fmt.Errorf(description),
			ErrorCode:   statusCode,
			Description: description,
			URI:         "",
			StatusCode:  statusCode,
			Header:      map[string][]string{},
		}
	}
	return &errors.Response{
		Error:       err,
		ErrorCode:   0,
		Description: "",
		URI:         "",
		StatusCode:  500,
		Header:      map[string][]string{},
	}
}

func (svc service) UserAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	token, err := authenticateUser(r, svc.config.LndHubUrl)
	if err != nil {
		logrus.Error(err)
		sentry.CaptureException(err)
		return "", err
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return svc.config.JWTSecret, nil
	})
	if err != nil {
		return "", err
	}
	if claims["id"] == nil {
		return "", fmt.Errorf("Cannot authenticate user, token does not contain user id")
	}
	return fmt.Sprintf("%.0f", claims["id"].(float64)), nil
}

func authenticateUser(r *http.Request, lndhubUrl string) (token string, err error) {
	err = r.ParseForm()
	//look for login/password in form data
	//but also allow basic auth, form data only works with POST requests
	login, password, ok := r.BasicAuth()
	if ok {
		r.Form.Add("login", login)
		r.Form.Add("password", password)
	}
	if err != nil {
		return "", fmt.Errorf("Error parsing form data %s", err.Error())
	}
	login = r.Form.Get("login")
	password = r.Form.Get("password")

	if login == "" && password == "" {
		return "", fmt.Errorf("Cannot authenticate user, form data missing.")
	}

	if login == "" || password == "" {
		return "", fmt.Errorf("Cannot authenticate user, login or password missing.")
	}
	//authenticate user against lndhub
	resp, err := http.PostForm(fmt.Sprintf("%s/auth", lndhubUrl), r.Form)
	if err != nil {
		return "", fmt.Errorf("Error authenticating user %s", err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Cannot authenticate user, login or password wrong.")
	}
	//return access code
	tokenResponse := &TokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)
	if err != nil {
		return "", fmt.Errorf("Error authenticating user %s", err.Error())
	}
	return tokenResponse.AccessToken, nil
}

func preRedirectErrorHandler(w http.ResponseWriter, r *server.AuthorizeRequest, err error) error {
	logrus.WithField("Authorize request", r).Error(err)
	sentry.CaptureException(err)
	return err
}

func (svc *service) AuthorizeScopeHandler(w http.ResponseWriter, r *http.Request) (scope string, err error) {
	requestedScope := r.FormValue("scope")
	if requestedScope == "" {
		return "", fmt.Errorf("Empty scope is not allowed")
	}
	for _, scope := range strings.Split(requestedScope, " ") {
		if _, found := svc.scopes[scope]; !found {
			err = fmt.Errorf("Scope not allowed: %s", scope)
			sentry.CaptureException(err)
			return "", err
		}
	}
	return requestedScope, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (svc *service) UserAuthorizeMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := svc.UserAuthorizeHandler(w, r)
		if err != nil {
			logrus.Errorf("Error authenticating user %s", err.Error())
			sentry.CaptureException(err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), CONTEXT_ID_KEY, id))
		h.ServeHTTP(w, r)
	})
}
