package integrationtests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"oauth2server/constants"
	"oauth2server/internal/clients"
	"oauth2server/service"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

// TODO: move test
func TestCreateClient(t *testing.T) {
	svc, err := service.InitService(testConfig)
	assert.NoError(t, err)
	svc.OauthServer.SetUserAuthorizationHandler(controller.UserAuthorizeHandler)
	svc.OauthServer.SetInternalErrorHandler(controller.InternalErrorHandler)
	svc.OauthServer.SetAuthorizeScopeHandler(controller.AuthorizeScopeHandler)
	_, err = svc.InitGateways()
	assert.NoError(t, err)
	reqBody := testClient
	resp, err := createClient(controller, &reqBody)
	assert.NoError(t, err)
	// check length of id, secret
	assert.Equal(t, constants.ClientIdLength, len(resp.ClientId))
	assert.Equal(t, constants.ClientSecretLength, len(resp.ClientSecret))
	// check other fields
	assert.Equal(t, reqBody.Name, resp.Name)
	assert.Equal(t, reqBody.ImageUrl, resp.ImageUrl)
	// look up object in database and check fields
	client, err := svc.ClientStore.GetByID(context.Background(), resp.ClientId)
	assert.NoError(t, err)
	assert.Equal(t, reqBody.Domain, client.GetDomain())
	assert.Equal(t, resp.ClientSecret, client.GetSecret())
	// try to create a client without a valid domain
	reqBody.Domain = "invalid"
	_, err = createClient(controller, &reqBody)
	assert.Error(t, err)
	// update the client
	reqBody.Name = "new name"
	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(reqBody)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, "/admin/clients/{clientId}", &buf)
	req = mux.SetURLVars(req, map[string]string{
		"clientId": resp.ClientId,
	})
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	http.HandlerFunc(controller.UpdateClientMetadataHandler).ServeHTTP(rec, req)
	assert.Equal(t, rec.Result().StatusCode, http.StatusOK)
	found := &clients.ClientMetaData{}
	err = svc.DB.Find(found, &clients.ClientMetaData{ClientID: resp.ClientId}).Error
	assert.NoError(t, err)
	assert.Equal(t, "new name", found.Name)
	assert.Equal(t, testClient.ImageUrl, found.ImageUrl)
	err = dropTables(svc.DB, constants.ClientTableName, constants.ClientMetadataTableName, constants.TokenTableName)
	assert.NoError(t, err)
}
