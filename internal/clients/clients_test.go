package clients

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

var testScopes = map[string]string{}
var testClient = CreateClientRequest{
	Domain:   "http://example.com",
	Name:     "Test",
	ImageUrl: "https://example.com/image.jpg",
	URL:      "https://example.com",
}

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
