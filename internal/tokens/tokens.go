package tokens

import (
	"encoding/json"
	"fmt"
	"net/http"
	"oauth2server/internal/middleware"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	oauthErrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

var CONTEXT_ID_KEY string = "ID"

type service struct {
	//todo: don't expose oauthserver for code cleanliness
	OauthServer *server.Server
	scopes      map[string]string
	config      Config
}

func RegisterRoutes(r *mux.Router, svc *service) {
	r.HandleFunc("/oauth/authorize", svc.AuthorizationHandler)
	r.HandleFunc("/oauth/token", svc.TokenHandler)
	r.HandleFunc("/oauth/scopes", svc.ScopeHandler)
	r.HandleFunc("/oauth/token/introspect", svc.TokenIntrospectHandler).Methods(http.MethodGet)
}

func NewService(cs oauth2.ClientStore, ts oauth2.TokenStore, scopes map[string]string, userAuth server.UserAuthorizationHandler) (result *service, err error) {
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
		OauthServer: srv,
		scopes:      scopes,
	}
	srv.SetUserAuthorizationHandler(userAuth)
	srv.SetInternalErrorHandler(svc.InternalErrorHandler)
	srv.SetAuthorizeScopeHandler(svc.AuthorizeScopeHandler)
	srv.SetPreRedirectErrorHandler(preRedirectErrorHandler)
	svc.config = conf

	return svc, nil
}

func (svc *service) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	err := svc.OauthServer.HandleAuthorizeRequest(w, r)
	if err != nil {
		sentry.CaptureException(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (svc *service) TokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	gt, tgr, err := svc.OauthServer.ValidationTokenRequest(r)
	if err != nil {
		sentry.CaptureException(err)
		svc.tokenError(w, err)
		return
	}

	ti, err := svc.OauthServer.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		sentry.CaptureException(err)
		svc.tokenError(w, err)
		return
	}

	svc.token(w, svc.OauthServer.GetTokenData(ti), nil)
}

func (svc *service) TokenIntrospectHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenInfo, err := svc.OauthServer.Manager.LoadAccessToken(r.Context(), token)
	if err != nil {
		svc.tokenError(w, err)
		return
	}
	// for middleware
	lti := r.Context().Value("token_info")
	if lti != nil {
		logTokenInfo := lti.(*middleware.LogTokenInfo)
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
	data, statusCode, header := svc.OauthServer.GetErrorData(err)
	logrus.
		WithField("error_description", data["error_description"]).
		WithField("error", err).
		Error("token error")
	return svc.token(w, data, header, statusCode)
}

func (svc *service) token(w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) error {
	if fn := svc.OauthServer.ResponseTokenHandler; fn != nil {
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
