package integrationtests

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oauth2server/constants"
	"oauth2server/models"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

func TestGateway(t *testing.T) {
	//init test origin server at localhost:8082
	//make a channel to intercept the jwt token
	jwtChan := make(chan string, 1)
	originServerMsg := "Hi, you have reached the origin server"
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwtChan <- r.Header.Get("Authorization")
		_, err := w.Write([]byte(originServerMsg))
		assert.NoError(t, err)
	}))
	l, _ := net.Listen("tcp", "localhost:8082")
	ts.Listener = l
	ts.Start()
	defer ts.Close()

	svc, controller := initService(t)
	gateways, err := svc.InitGateways()
	assert.NoError(t, err)
	assert.Equal(t, 2, len(gateways))
	cli, err := createClient(controller, &testClient)
	assert.NoError(t, err)
	rec, err := fetchCode(cli.ClientId, testClient.Domain, "balance:read", controller)
	assert.NoError(t, err)
	loc := rec.Header().Get("Location")
	redirect, err := url.Parse(loc)
	assert.NoError(t, err)
	code := redirect.Query().Get("code")
	assert.NotEmpty(t, code)
	rec, err = fetchToken(cli.ClientId, cli.ClientSecret, code, testClient.Domain, controller)
	assert.NoError(t, err)
	resp := &TokenResponse{}
	err = json.NewDecoder(rec.Body).Decode(resp)
	assert.NoError(t, err)
	//make API request
	req, err := http.NewRequest(http.MethodGet, "/balance", nil)
	u := &models.LogTokenInfo{}
	req = req.WithContext(context.WithValue(req.Context(), "token_info", u))
	req.Header.Set("Authorization", resp.AccessToken)
	assert.NoError(t, err)
	rec = httptest.NewRecorder()
	//we're not testing the gateway selection logic at the moment
	gateways[0].ServeHTTP(rec, req)
	//assert that we get a response from the right backend
	assert.Equal(t, originServerMsg, rec.Body.String())
	//check backend server that we got a jwt token
	token := <-jwtChan
	assert.Contains(t, token, "Bearer ")
	claims := jwt.MapClaims{}
	jwtToken := strings.TrimPrefix(token, "Bearer ")
	parsed, err := jwt.ParseWithClaims(jwtToken, claims, func(token *jwt.Token) (interface{}, error) {
		return svc.Config.JWTSecret, nil
	})
	assert.NoError(t, err)
	assert.True(t, parsed.Valid)
	assert.Positive(t, claims["id"])
	assert.False(t, claims["isRefresh"].(bool))

	//make request with token for wrong scope, assert that this fails
	req, err = http.NewRequest(http.MethodGet, "/invoices/incoming", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", resp.AccessToken)
	assert.NoError(t, err)
	rec = httptest.NewRecorder()
	gateways[1].ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)

	err = dropTables(svc.DB, constants.ClientTableName, constants.ClientMetadataTableName, constants.TokenTableName)
	assert.NoError(t, err)
}
