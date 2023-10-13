package tokens

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/stretchr/testify/assert"
)

type MockClientStore struct{}

var testClient = &models.Client{
	ID:     "client_id",
	Secret: "client_secret",
	Domain: "http://domain.com",
	UserID: "123id",
}

var testScopes = map[string]string{
	"balance:read": "Read your balance",
}

var testAccountLogin = "login"
var testAccountPassword = "password"
var testUserId = "123userid"

// GetByID implements oauth2.ClientStore.
func (MockClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	return testClient, nil
}
func mockAuthorize(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	return testUserId, nil
}

func TestCreateToken(t *testing.T) {
	//setup test service
	ts := NewInmemStore()
	tokenSvc, err := NewService(MockClientStore{}, ts, testScopes, mockAuthorize)
	assert.NoError(t, err)
	rec, err := fetchCode(testClient.ID, testClient.Domain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	//extract code from Location headers
	loc := rec.Header().Get("Location")
	redirect, err := url.Parse(loc)
	assert.NoError(t, err)
	code := redirect.Query().Get("code")
	assert.NotEmpty(t, code)
	//make request to fetch token
	rec = httptest.NewRecorder()
	rec, err = fetchToken(testClient.ID, testClient.Secret, code, testClient.Domain, tokenSvc.TokenHandler)
	assert.NoError(t, err)
	//validate access token, refresh token with object from database
	resp := &TokenResponse{}
	err = json.NewDecoder(rec.Body).Decode(resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "balance:read", resp.Scope)
	assert.Equal(t, tokenSvc.config.AccessTokenExpSeconds, resp.ExpiresIn)
}

func fetchToken(id, secret, code, redirect string, handler http.HandlerFunc) (rec *httptest.ResponseRecorder, err error) {
	values := url.Values{}
	values.Add("redirect_uri", redirect)
	values.Add("grant_type", "authorization_code")
	values.Add("code", code)
	req, err := http.NewRequest("POST", "/oauth/token", strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	rec = httptest.NewRecorder()
	http.HandlerFunc(handler).ServeHTTP(rec, req)
	return rec, err
}

func fetchCode(id, redirect, scope string, handler http.HandlerFunc) (rec *httptest.ResponseRecorder, err error) {
	values := url.Values{}
	values.Add("redirect_uri", redirect)
	values.Add("response_type", "code")
	values.Add("client_id", id)
	values.Add("scope", scope)
	values.Add("login", testAccountLogin)
	values.Add("password", testAccountPassword)
	req, err := http.NewRequest("POST", "/oauth/authorize", strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	http.HandlerFunc(handler).ServeHTTP(rec, req)
	return rec, err
}

//todo: get this working again
//func TestListDeleteTokensForClient(t *testing.T) {
//	svc, err := service.InitService(testConfig)
//	assert.NoError(t, err)
//	controller := &controllers.OAuthController{
//		Service: svc,
//	}
//	svc.OauthServer.SetUserAuthorizationHandler(controller.UserAuthorizeHandler)
//	svc.OauthServer.SetInternalErrorHandler(controller.InternalErrorHandler)
//	svc.OauthServer.SetAuthorizeScopeHandler(controller.AuthorizeScopeHandler)
//	_, err = svc.InitGateways()
//	assert.NoError(t, err)
//	cli, err := createClient(controller, &testClient)
//	assert.NoError(t, err)
//	//create code using user credentials
//	rec, err := fetchCode(cli.ClientId, testClient.Domain, "balance:read", controller)
//	assert.NoError(t, err)
//	//extract code from Location headers
//	loc := rec.Header().Get("Location")
//	redirect, err := url.Parse(loc)
//	assert.NoError(t, err)
//	code := redirect.Query().Get("code")
//	//make request to fetch token
//	_, err = fetchToken(cli.ClientId, cli.ClientSecret, code, testClient.Domain, controller)
//	assert.NoError(t, err)
//	//list clients
//	req, err := http.NewRequest(http.MethodGet, "/clients", nil)
//	assert.NoError(t, err)
//	req.SetBasicAuth(testAccountLogin, testAccountPassword)
//	rec = httptest.NewRecorder()
//	controller.UserAuthorizeMiddleware(http.HandlerFunc(controller.ListClientHandler)).ServeHTTP(rec, req)
//	clients := []clients.ListClientsResponse{}
//	err = json.NewDecoder(rec.Body).Decode(&clients)
//	assert.NoError(t, err)
//	assert.NotEmpty(t, clients)
//	assert.Equal(t, testClient.Name, clients[0].Name)
//	//delete client
//	req.Method = http.MethodDelete
//	req = mux.SetURLVars(req, map[string]string{
//		"clientId": clients[0].ID,
//	})
//	rec = httptest.NewRecorder()
//	controller.UserAuthorizeMiddleware(http.HandlerFunc(controller.DeleteClientHandler)).ServeHTTP(rec, req)
//	assert.Equal(t, rec.Result().StatusCode, http.StatusOK)
//	//list clients
//	rec = httptest.NewRecorder()
//	controller.UserAuthorizeMiddleware(http.HandlerFunc(controller.ListClientHandler)).ServeHTTP(rec, req)
//	err = json.NewDecoder(rec.Body).Decode(&clients)
//	assert.NoError(t, err)
//	assert.Empty(t, clients)
//	err = dropTables(svc.DB, constants.ClientTableName, constants.ClientMetadataTableName, constants.TokenTableName)
//	assert.NoError(t, err)
//}
//
