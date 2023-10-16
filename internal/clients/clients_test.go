package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	"github.com/getsentry/sentry-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var testScopes = map[string]string{}
var testClient = CreateClientRequest{
	Domain:   "http://example.com",
	Name:     "Test",
	ImageUrl: "https://example.com/image.jpg",
	URL:      "https://example.com",
}

var testAccountLogin = "login"
var testAccountPassword = "password"
var testAccountUserId = "123"

func TestCreateClient(t *testing.T) {
	inmem := NewInMem()
	svc := NewService(inmem, testScopes)
	reqBody := testClient
	resp := &CreateClientResponse{}
	err := httpReq(svc.CreateClientHandler, http.MethodPost, "/admin/clients", "", &reqBody, resp)
	assert.NoError(t, err)
	// check length of id, secret
	assert.Equal(t, ClientIdLength, len(resp.ClientId))
	assert.Equal(t, ClientSecretLength, len(resp.ClientSecret))
	// check other fields
	assert.Equal(t, reqBody.Name, resp.Name)
	assert.Equal(t, reqBody.ImageUrl, resp.ImageUrl)
	// try to create a client without a valid domain
	reqBody.Domain = "invalid"
	err = httpReq(svc.CreateClientHandler, http.MethodPost, "/admin/clients", "", &reqBody, &CreateClientResponse{})
	assert.Error(t, err)
	// update the client
	reqBody.Domain = "http://localhost:8080"
	reqBody.Name = "new name"
	err = httpReq(svc.UpdateClientMetadataHandler, http.MethodPut, "/admin/clients", resp.ClientId, reqBody, &CreateClientResponse{})
	assert.NoError(t, err)

	result := &ListClientsResponse{}
	err = httpReq(svc.FetchClientHandler, http.MethodGet, "/admin/clients", resp.ClientId, nil, result)
	assert.NoError(t, err)
	assert.Equal(t, "new name", result.Name)
	assert.Equal(t, testClient.ImageUrl, result.ImageURL)
}

// helper func, encodes a http request and decodes the response in a struct
func httpReq(handler func(http.ResponseWriter, *http.Request), method, url, clientId string, body interface{}, resp interface{}) (err error) {
	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		return err
	}
	if clientId != "" {
		req = mux.SetURLVars(req, map[string]string{
			"clientId": clientId,
		})
	}

	rec := httptest.NewRecorder()
	http.HandlerFunc(handler).ServeHTTP(rec, req)
	status := rec.Result().StatusCode
	if status != http.StatusOK {
		return fmt.Errorf("create client request failed %s", rec.Body.String())
	}
	return json.NewDecoder(rec.Body).Decode(resp)

}
func MockUserAuthorizeMiddleware(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := authenticateUser(r)
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

func authenticateUser(r *http.Request) (userId string, err error) {
	err = r.ParseForm()
	login, pw, ok := r.BasicAuth()
	if !ok {
		return "", fmt.Errorf("bad auth")
	}
	if login != testAccountLogin || pw != testAccountPassword {
		return "", fmt.Errorf("bad auth")
	}
	return testAccountUserId, nil
}

func TestListTokensForClient(t *testing.T) {
	inmem := NewInMem().(*InMem)
	svc := NewService(inmem, testScopes)
	reqBody := testClient
	resp := &CreateClientResponse{}
	err := httpReq(svc.CreateClientHandler, http.MethodPost, "/admin/clients", "", &reqBody, resp)
	assert.NoError(t, err)
	//add token for client for user
	inmem.AddToken(context.Background(), oauth2gorm.TokenStoreItem{
		Access:   "123access",
		ClientID: resp.ClientId,
		UserID:   testAccountUserId,
		Scope:    "balance:read",
	})
	//list clients
	//use mock middleware
	req, err := http.NewRequest(http.MethodGet, "/clients", nil)
	assert.NoError(t, err)
	req.SetBasicAuth(testAccountLogin, testAccountPassword)
	clients := []ListClientsResponse{}
	rec := httptest.NewRecorder()
	http.Handler(MockUserAuthorizeMiddleware(svc.ListClientsForUserHandler)).ServeHTTP(rec, req)
	err = json.NewDecoder(rec.Body).Decode(&clients)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, clients)
	assert.Equal(t, testClient.Name, clients[0].Name)
}
