package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

const testToken = "TEST1234"

var testJWTSecret = []byte("SUPERSECRET")

func testTokenFunc(ctx context.Context, token string) (result oauth2.TokenInfo, err error) {

	if token != testToken {
		return result, fmt.Errorf("unauthorized")
	}
	return &models.Token{
		ClientID:            "TEST",
		UserID:              "123",
		RedirectURI:         "",
		Scope:               "balance:read",
		Code:                "",
		CodeChallenge:       "",
		CodeChallengeMethod: "",
		CodeCreateAt:        time.Time{},
		CodeExpiresIn:       0,
		Access:              testToken,
		AccessCreateAt:      time.Time{},
		AccessExpiresIn:     0,
		Refresh:             "",
		RefreshCreateAt:     time.Time{},
		RefreshExpiresIn:    0,
	}, nil
}

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

	gateways, err := InitGateways("test_targets.json", testTokenFunc, testJWTSecret)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(gateways))
	//make API request
	req, err := http.NewRequest(http.MethodGet, "/balance", nil)
	req.Header.Set("Authorization", testToken)
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	//wrap gateway with middleware
	//we're not testing the gateway selection logic at the moment
	gateways[0].ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	//assert that we get a response from the right backend
	assert.Equal(t, originServerMsg, rec.Body.String())
	//check backend server that we got a jwt token
	token := <-jwtChan
	assert.Contains(t, token, "Bearer ")
	claims := jwt.MapClaims{}
	jwtToken := strings.TrimPrefix(token, "Bearer ")
	parsed, err := jwt.ParseWithClaims(jwtToken, claims, func(token *jwt.Token) (interface{}, error) {
		return testJWTSecret, nil
	})
	assert.NoError(t, err)
	assert.True(t, parsed.Valid)
	assert.Positive(t, claims["id"])
	assert.False(t, claims["isRefresh"].(bool))

	//make request with token for wrong scope, assert that this fails
	req, err = http.NewRequest(http.MethodGet, "/invoices/incoming", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", testToken)
	assert.NoError(t, err)
	rec = httptest.NewRecorder()
	gw2 := gateways[1]
	gw2.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}

func TestGenerateLNDHubToken(t *testing.T) {
	secret := []byte("secret")
	expirySeconds := 1
	clientId := "1"
	userId := "2"
	token, err := generateLNDHubAccessToken(secret, expirySeconds, userId, clientId)
	assert.NoError(t, err)
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, clientId, claims["clientId"])
	assert.Equal(t, userId, fmt.Sprintf("%.0f", claims["id"].(float64)))

}
