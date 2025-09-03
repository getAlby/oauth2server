package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

const (
	balanceToken = "TESTBALANCE123"
	invoiceToken = "TESTINVOICE123"
	accountToken = "TESTACCOUNT123"
)

var testJWTSecret = []byte("SUPERSECRET")

func testTokenFunc(ctx context.Context, token string) (result oauth2.TokenInfo, err error) {
	tokenScopes := map[string]string{
		accountToken: "account:read",
		balanceToken: "balance:read",
		invoiceToken: "invoices:read",
	}

	scope, ok := tokenScopes[token]
	if !ok {
		return result, errors.ErrInvalidAccessToken
	}

	return &models.Token{
		ClientID: "TEST",
		UserID:   "123",
		Scope:    scope,
		Access:   token,
	}, nil
}

func startOriginServer(t *testing.T) (*httptest.Server, chan string, string) {
	t.Helper()
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
	return ts, jwtChan, originServerMsg
}

func initTestGateways(t *testing.T) []*OriginServer {
	t.Helper()
	gateways, err := InitGateways("test_targets.json", testTokenFunc, testJWTSecret)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(gateways))
	return gateways
}

func TestGateway_WithToken(t *testing.T) {
	ts, jwtChan, originServerMsg := startOriginServer(t)
	defer ts.Close()

	gateways := initTestGateways(t)

	req, err := http.NewRequest(http.MethodGet, "/balance", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", balanceToken)

	rec := httptest.NewRecorder()
	gateways[0].ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, originServerMsg, rec.Body.String())

	// JWT forwarded
	token := <-jwtChan
	assert.Contains(t, token, "Bearer ")
	jwtToken := strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(jwtToken, claims, func(token *jwt.Token) (interface{}, error) {
		return testJWTSecret, nil
	})
	assert.NoError(t, err)
	assert.True(t, parsed.Valid)
	assert.Positive(t, claims["id"])
	assert.False(t, claims["isRefresh"].(bool))
}

func TestGateway_MissingToken(t *testing.T) {
	ts, _, _ := startOriginServer(t)
	defer ts.Close()

	gateways := initTestGateways(t)

	req, err := http.NewRequest(http.MethodGet, "/balance", nil)
	assert.NoError(t, err)

	rec := httptest.NewRecorder()
	gateways[0].ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}

func TestGateway_WrongToken(t *testing.T) {
	ts, _, _ := startOriginServer(t)
	defer ts.Close()

	gateways := initTestGateways(t)

	req, err := http.NewRequest(http.MethodGet, "/invoices/incoming", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", balanceToken) // wrongly scoped token

	rec := httptest.NewRecorder()
	gateways[1].ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)
}

func TestGateway_AllowPublicAccess_WithoutToken(t *testing.T) {
	ts, jwtChan, originServerMsg := startOriginServer(t)
	defer ts.Close()

	gateways := initTestGateways(t)

	req, err := http.NewRequest(http.MethodGet, "/lsp/channels", nil) // allowUnauthorized
	assert.NoError(t, err)

	rec := httptest.NewRecorder()
	gateways[2].ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, originServerMsg, rec.Body.String())

	// No token should be forwarded
	token := <-jwtChan
	assert.Empty(t, token)
}

func TestGateway_AllowPublicAccess_WithToken(t *testing.T) {
	ts, jwtChan, originServerMsg := startOriginServer(t)
	defer ts.Close()

	gateways := initTestGateways(t)

	// wrong token -> unauthorized
	req, err := http.NewRequest(http.MethodGet, "/lsp/channels", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", balanceToken)
	rec := httptest.NewRecorder()
	gateways[2].ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)

	// correct token -> success and JWT forwarded
	req2, err := http.NewRequest(http.MethodGet, "/lsp/channels", nil)
	assert.NoError(t, err)
	req2.Header.Set("Authorization", accountToken)
	rec2 := httptest.NewRecorder()
	gateways[2].ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, originServerMsg, rec2.Body.String())

	token := <-jwtChan
	assert.Contains(t, token, "Bearer ")
	jwtToken := strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(jwtToken, claims, func(token *jwt.Token) (interface{}, error) {
		return testJWTSecret, nil
	})
	assert.NoError(t, err)
	assert.True(t, parsed.Valid)
	assert.Positive(t, claims["id"])
	assert.False(t, claims["isRefresh"].(bool))
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
