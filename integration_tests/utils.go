package integrationtests

import (
	"fmt"
	"oauth2server/controllers"
	"oauth2server/internal/clients"
	"oauth2server/service"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

// account on lndhub.regtest.getalby.com
var testAccountLogin = os.Getenv("LNDHUB_LOGIN")
var testAccountPassword = os.Getenv("LNDHUB_PASSWORD")

var testConfig = &service.Config{
	Port:                   8081,
	JWTSecret:              []byte(os.Getenv("LNDHUB_JWT_SECRET")),
	DatabaseUri:            "postgres://user:password@localhost/oauthtests?sslmode=disable",
	LndHubUrl:              "https://lndhub.regtest.getalby.com",
	TargetFile:             "test_targets.json",
	AccessTokenExpSeconds:  3600,
	RefreshTokenExpSeconds: 3600,
}

var testClient = clients.CreateClientRequest{
	Domain:   "http://example.com",
	Name:     "Test",
	ImageUrl: "https://example.com/image.jpg",
	URL:      "https://example.com",
}

func initService(t *testing.T) (svc *service.Service, controller *controllers.OAuthController) {
	svc, err := service.InitService(testConfig)
	assert.NoError(t, err)
	controller = &controllers.OAuthController{
		Service: svc,
	}
	svc.OauthServer.SetUserAuthorizationHandler(controller.UserAuthorizeHandler)
	svc.OauthServer.SetInternalErrorHandler(controller.InternalErrorHandler)
	svc.OauthServer.SetAuthorizeScopeHandler(controller.AuthorizeScopeHandler)
	return svc, controller
}
func dropTables(db *gorm.DB, tables ...string) error {
	for _, table := range tables {
		err := db.Exec(fmt.Sprintf("delete from %s", table)).Error
		if err != nil {
			return err
		}
	}
	return nil
}
