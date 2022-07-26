package integrationtests

import (
	"oauth2server/controllers"
	"oauth2server/service"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testConfig = &service.Config{
	Port:                   8081,
	JWTSecret:              []byte("supersecret"),
	DatabaseUri:            "postgres://user:password@localhost:5432/oauthtests?sslmode=disable",
	LndHubUrl:              "https://lndhub.regtest.getalby.com",
	TargetFile:             "/Users/kwinten/Alby/oauth2server/targets.json",
	AccessTokenExpSeconds:  3600,
	RefreshTokenExpSeconds: 3600,
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

}
