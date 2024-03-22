package tokens

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oauth2server/internal/middleware"
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
	rec, err = fetchToken(testClient.ID, testClient.Secret, code, testClient.Domain, tokenSvc.TokenHandler)
	assert.NoError(t, err)
	//validate access token, refresh token with object from database
	//use the lndhub token response struct because it has the same structure
	resp := &middleware.LNDHubTokenResponse{}
	err = json.NewDecoder(rec.Body).Decode(resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "balance:read", resp.Scope)
	assert.Equal(t, tokenSvc.config.AccessTokenExpSeconds, resp.ExpiresIn)
}

func TestDomainRedirects(t *testing.T) {
	testClient.Domain = "http://sub.domain.com"
	//setup test service
	ts := NewInmemStore()
	tokenSvc, err := NewService(MockClientStore{}, ts, testScopes, mockAuthorize)
	assert.NoError(t, err)

	// Test incorrect scheme
	subdomain := "https://sub.domain.com"
	rec, _ := fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusBadRequest)

	// Test incorrect domain
	subdomain = "http://big.domain.com"
	rec, _ = fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusBadRequest)

	// Test valid domain
	subdomain = "http://sub.domain.com"
	rec, _ = fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusFound)

	// Test localhost domain
	{
		testClient.Domain = "http://localhost:8080"
		//setup test service
		ts = NewInmemStore()
		tokenSvc, err = NewService(MockClientStore{}, ts, testScopes, mockAuthorize)
		assert.NoError(t, err)
	
		// Test incorrect domain
		redirect := "http://localhost:8081"
		rec, _ = fetchCode(testClient.ID, redirect, "balance:read", tokenSvc.AuthorizationHandler)
		assert.NoError(t, err)
		assert.Equal(t, rec.Result().StatusCode, http.StatusBadRequest)
		
		// Test incorrect scheme
		redirect = "https://localhost:8080"
		rec, _ = fetchCode(testClient.ID, redirect, "balance:read", tokenSvc.AuthorizationHandler)
		assert.NoError(t, err)
		assert.Equal(t, rec.Result().StatusCode, http.StatusBadRequest)
	
		// Test valid domain
		redirect = "http://localhost:8080"
		rec, err = fetchCode(testClient.ID, redirect, "balance:read", tokenSvc.AuthorizationHandler)
		assert.NoError(t, err)
		assert.Equal(t, rec.Result().StatusCode, http.StatusFound)
	}

	// Test Wildcard Domains

	testClient.Domain = "http://*.domain.com"
	//setup test service
	ts = NewInmemStore()
	tokenSvc, err = NewService(MockClientStore{}, ts, testScopes, mockAuthorize)
	assert.NoError(t, err)

	// Test incorrect domain
	subdomain = "http://some.big.domain.com"
	rec, _ = fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusBadRequest)

	// Test valid subdomain
	subdomain = "http://big.domain.com"
	rec, err = fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusFound)

	testClient.Domain = "http://very.*.domain.com"
	//setup test service
	ts = NewInmemStore()
	tokenSvc, err = NewService(MockClientStore{}, ts, testScopes, mockAuthorize)
	assert.NoError(t, err)

	// Test incorrect domain
	subdomain = "http://veryyy.big.domain.com"
	rec, _ = fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusBadRequest)

	// Test valid subdomain
	subdomain = "http://very.big.domain.com"
	rec, err = fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusFound)

	testClient.Domain = "http://*.some.big.domain.com"
	//setup test service
	ts = NewInmemStore()
	tokenSvc, err = NewService(MockClientStore{}, ts, testScopes, mockAuthorize)
	assert.NoError(t, err)

	// Test incorrect domains
	subdomain = "http://some.big.domain.com"
	rec, _ = fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusBadRequest)

	subdomain = "http://it.is.some.big.domain.com"
	rec, _ = fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusBadRequest)

	// Test valid subdomains
	subdomain = "http://awe.some.big.domain.com"
	rec, err = fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusFound)

	subdomain = "http://123whole.some.big.domain.com"
	rec, err = fetchCode(testClient.ID, subdomain, "balance:read", tokenSvc.AuthorizationHandler)
	assert.NoError(t, err)
	assert.Equal(t, rec.Result().StatusCode, http.StatusFound)
	//extract code from Location headers
	loc := rec.Header().Get("Location")
	redirect, err := url.Parse(loc)
	assert.NoError(t, err)
	code := redirect.Query().Get("code")
	assert.NotEmpty(t, code)
	//make request to fetch token
	rec, err = fetchToken(testClient.ID, testClient.Secret, code, subdomain, tokenSvc.TokenHandler)
	assert.NoError(t, err)
	//validate access token, refresh token with object from database
	//use the lndhub token response struct because it has the same structure
	resp := &middleware.LNDHubTokenResponse{}
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
