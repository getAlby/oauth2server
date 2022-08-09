package integrationtests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oauth2server/constants"
	"oauth2server/controllers"
	"oauth2server/models"
	"oauth2server/service"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestCreateToken(t *testing.T) {
	svc, controller := initService(t)
	_, err := svc.InitGateways()
	assert.NoError(t, err)
	cli, err := createClient(controller, &testClient)
	assert.NoError(t, err)
	//create code using user credentials
	rec, err := fetchCode(cli.ClientId, testClient.Domain, "balance:read", controller)
	assert.NoError(t, err)
	//extract code from Location headers
	loc := rec.Header().Get("Location")
	redirect, err := url.Parse(loc)
	assert.NoError(t, err)
	code := redirect.Query().Get("code")
	assert.NotEmpty(t, code)
	//make request to fetch token
	rec, err = fetchToken(cli.ClientId, cli.ClientSecret, code, testClient.Domain, controller)
	assert.NoError(t, err)
	//validate access token, refresh token with object from database
	resp := &TokenResponse{}
	err = json.NewDecoder(rec.Body).Decode(resp)
	assert.NoError(t, err)
	tokenInfo, err := svc.OauthServer.Manager.LoadAccessToken(context.Background(), resp.AccessToken)
	assert.NoError(t, err)
	assert.NotNil(t, tokenInfo)
	assert.Equal(t, tokenInfo.GetAccess(), resp.AccessToken)
	assert.Equal(t, tokenInfo.GetRefresh(), resp.RefreshToken)
	assert.Equal(t, "balance:read", resp.Scope)
	assert.Equal(t, testConfig.AccessTokenExpSeconds, resp.ExpiresIn)
	err = dropTables(svc.DB, constants.ClientTableName, constants.ClientMetadataTableName, constants.TokenTableName)
	assert.NoError(t, err)
}

func fetchToken(id, secret, code, redirect string, controller *controllers.OAuthController) (rec *httptest.ResponseRecorder, err error) {
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
	http.HandlerFunc(controller.TokenHandler).ServeHTTP(rec, req)
	return rec, err
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

func fetchCode(id, redirect, scope string, controller *controllers.OAuthController) (rec *httptest.ResponseRecorder, err error) {
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
	http.HandlerFunc(controller.AuthorizationHandler).ServeHTTP(rec, req)
	return rec, err
}

func TestListDeleteTokensForClient(t *testing.T) {
	svc, err := service.InitService(testConfig)
	assert.NoError(t, err)
	controller := &controllers.OAuthController{
		Service: svc,
	}
	svc.OauthServer.SetUserAuthorizationHandler(controller.UserAuthorizeHandler)
	svc.OauthServer.SetInternalErrorHandler(controller.InternalErrorHandler)
	svc.OauthServer.SetAuthorizeScopeHandler(controller.AuthorizeScopeHandler)
	_, err = svc.InitGateways()
	assert.NoError(t, err)
	cli, err := createClient(controller, &testClient)
	assert.NoError(t, err)
	//create code using user credentials
	rec, err := fetchCode(cli.ClientId, testClient.Domain, "balance:read", controller)
	assert.NoError(t, err)
	//extract code from Location headers
	loc := rec.Header().Get("Location")
	redirect, err := url.Parse(loc)
	assert.NoError(t, err)
	code := redirect.Query().Get("code")
	//make request to fetch token
	_, err = fetchToken(cli.ClientId, cli.ClientSecret, code, testClient.Domain, controller)
	assert.NoError(t, err)
	//list clients
	req, err := http.NewRequest(http.MethodGet, "/clients", nil)
	assert.NoError(t, err)
	req.SetBasicAuth(testAccountLogin, testAccountPassword)
	rec = httptest.NewRecorder()
	controller.UserAuthorizeMiddleware(http.HandlerFunc(controller.ListClientHandler)).ServeHTTP(rec, req)
	clients := []models.ListClientsResponse{}
	err = json.NewDecoder(rec.Body).Decode(&clients)
	assert.NoError(t, err)
	assert.NotEmpty(t, clients)
	assert.Equal(t, testClient.Name, clients[0].Name)
	//delete client
	req.Method = http.MethodDelete
	req = mux.SetURLVars(req, map[string]string{
		"clientId": clients[0].ID,
	})
	rec = httptest.NewRecorder()
	controller.UserAuthorizeMiddleware(http.HandlerFunc(controller.DeleteClientHandler)).ServeHTTP(rec, req)
	assert.Equal(t, rec.Result().StatusCode, http.StatusOK)
	//list clients
	rec = httptest.NewRecorder()
	controller.UserAuthorizeMiddleware(http.HandlerFunc(controller.ListClientHandler)).ServeHTTP(rec, req)
	err = json.NewDecoder(rec.Body).Decode(&clients)
	assert.NoError(t, err)
	assert.Empty(t, clients)
	err = dropTables(svc.DB, constants.ClientTableName, constants.ClientMetadataTableName, constants.TokenTableName)
	assert.NoError(t, err)
}
