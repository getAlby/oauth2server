package integrationtests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oauth2server/constants"
	"oauth2server/controllers"
	"oauth2server/service"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateToken(t *testing.T) {
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
	fmt.Println(rec.HeaderMap)
	fmt.Println(rec.Body.String())
	loc := rec.Header().Get("Location")
	fmt.Println(loc)
	//make request to fetch token
	//validate access token, refresh token with object from database
	err = dropTables(svc.DB, constants.ClientTableName, constants.ClientMetadataTableName, constants.TokenTableName)
	assert.NoError(t, err)
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
	_, err = createClient(controller, &testClient)
	assert.NoError(t, err)
	//create code using user credentials
	//extract code from Location headers
	//make request to fetch token
	//validate access token, refresh token with object from database
	err = dropTables(svc.DB, constants.ClientTableName, constants.ClientMetadataTableName, constants.TokenTableName)
	assert.NoError(t, err)
}
