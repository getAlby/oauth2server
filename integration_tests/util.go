package integrationtests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"oauth2server/controllers"
	"oauth2server/models"

	"gorm.io/gorm"
)

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
