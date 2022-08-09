package integrationtests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"oauth2server/controllers"
	"oauth2server/models"
	"oauth2server/service"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

//account on lndhub.regtest.getalby.com
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

var testClient = models.CreateClientRequest{
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

func createClient(controller *controllers.OAuthController, reqBody *models.CreateClientRequest) (resp *models.CreateClientResponse, err error) {
	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "/admin/clients", &buf)
	if err != nil {
		return nil, err
	}
	rec := httptest.NewRecorder()
	http.HandlerFunc(controller.CreateClientHandler).ServeHTTP(rec, req)
	status := rec.Result().StatusCode
	if status != http.StatusOK {
		return nil, fmt.Errorf("create client request failed %s", rec.Body.String())
	}
	resp = &models.CreateClientResponse{}
	err = json.NewDecoder(rec.Body).Decode(resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
