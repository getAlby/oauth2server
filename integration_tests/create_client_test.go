package integrationtests

import (
	"context"
	"oauth2server/constants"
	"oauth2server/controllers"
	"oauth2server/models"
	"oauth2server/service"
	"testing"

	"github.com/stretchr/testify/assert"
)

//account on lndhub.regtest.getalby.com
var testAccountLogin = "yS0IRVe5F7v6rxr5M2jH"
var testAccountPassword = "Zw7TE46yR0m1GeVFNOui"

var testConfig = &service.Config{
	Port:                   8081,
	JWTSecret:              []byte("supersecret"),
	DatabaseUri:            "postgres://user:password@localhost/oauthtests?sslmode=disable",
	LndHubUrl:              "https://lndhub.regtest.getalby.com",
	TargetFile:             "../targets.json",
	AccessTokenExpSeconds:  3600,
	RefreshTokenExpSeconds: 3600,
}

var testClient = &models.CreateClientRequest{
	Domain:   "http://example.com",
	Name:     "Test",
	ImageUrl: "https://example.com/image.jpg",
	URL:      "https://example.com",
}

func TestCreateClient(t *testing.T) {

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
	reqBody := testClient
	resp, err := createClient(controller, reqBody)
	//check length of id, secret
	assert.Equal(t, constants.ClientIdLength, len(resp.ClientId))
	assert.Equal(t, constants.ClientSecretLength, len(resp.ClientSecret))
	//check other fields
	assert.Equal(t, reqBody.Name, resp.Name)
	assert.Equal(t, reqBody.ImageUrl, resp.ImageUrl)
	//look up object in database and check fields
	client, err := svc.ClientStore.GetByID(context.Background(), resp.ClientId)
	assert.NoError(t, err)
	assert.Equal(t, reqBody.Domain, client.GetDomain())
	assert.Equal(t, resp.ClientSecret, client.GetSecret())
	//try to create a client without a valid domain
	reqBody.Domain = "invalid"
	resp, err = createClient(controller, reqBody)
	assert.Error(t, err)
	err = dropTables(svc.DB, constants.ClientTableName, constants.ClientMetadataTableName, constants.TokenTableName)
	assert.NoError(t, err)
}
