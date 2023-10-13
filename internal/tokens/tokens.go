package tokens

import (
	"encoding/json"
	"net/http"
	"oauth2server/models"
	"strings"

	"github.com/getsentry/sentry-go"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type service struct {
	oauthServer server.Server
	scopes      map[string]string
}

func RegisterRoutes(r *mux.Router, svc *service) {
	r.HandleFunc("/oauth/authorize", svc.AuthorizationHandler)
	r.HandleFunc("/oauth/token", svc.TokenHandler)
	r.HandleFunc("/oauth/scopes", svc.ScopeHandler)
	r.HandleFunc("/oauth/token/introspect", svc.TokenIntrospectHandler).Methods(http.MethodGet)
}

func NewService(conf Config, scopes map[string]string) (result *service, err error) {
	//create oauth server from conf
	return nil, nil
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
