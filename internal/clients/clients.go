package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"oauth2server/constants"
	"oauth2server/models"

	"github.com/getsentry/sentry-go"
	"github.com/go-playground/validator"
	"gorm.io/gorm"

	"github.com/gorilla/mux"
	"github.com/labstack/gommon/random"
	"github.com/sirupsen/logrus"
)

type service struct {
	cs ClientStore
}

type ClientStore interface {
	Create(ctx context.Context, id, secret, domain, url, imageUrl, name string) error
	ListAllClients() (result []models.ClientMetaData, err error)
	UpdateClient(clientId, name, imageUrl, url string) (err error)
}

func NewService(cs ClientStore) *service {
	return &service{
		cs: cs,
	}
}

func RegisterRoutes(r *mux.Router, svc *service) {
	//these routes should not be publicly accesible
	r.HandleFunc("/admin/clients", svc.CreateClientHandler).Methods(http.MethodPost)
	r.HandleFunc("/admin/clients", svc.ListAllClientsHandler).Methods(http.MethodGet)
	r.HandleFunc("/admin/clients/{clientId}", svc.FetchClientHandler).Methods(http.MethodGet)
	r.HandleFunc("/admin/clients/{clientId}", svc.UpdateClientMetadataHandler).Methods(http.MethodPut)
}

func (svc *service) CreateClientHandler(w http.ResponseWriter, r *http.Request) {
	req := &models.CreateClientRequest{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		logrus.Errorf("Error decoding client info request %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("Could not parse create client request"))
		if err != nil {
			logrus.Error(err)
		}
		return
	}
	err = validator.New().Struct(req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			logrus.Error(err)
		}
		return
	}
	id := random.New().String(constants.ClientIdLength)
	var secret string
	if !req.Public {
		secret = random.New().String(constants.ClientSecretLength)
	}

	err = svc.cs.Create(r.Context(), id, secret, req.Domain, req.URL, req.ImageUrl, req.Name)
	if err != nil {
		logrus.Errorf("Error storing client info %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("Something went wrong while storing client info"))
		if err != nil {
			logrus.Error(err)
		}
	}

	w.Header().Add("Content-type", "application/json")
	err = json.NewEncoder(w).Encode(&models.CreateClientResponse{
		Name:         req.Name,
		ImageUrl:     req.ImageUrl,
		ClientId:     id,
		ClientSecret: secret,
	})
	if err != nil {
		logrus.Error(err)
	}
}

func (svc *service) ListAllClientsHandler(w http.ResponseWriter, r *http.Request) {
	result, err := svc.cs.ListAllClients()
	if err != nil {
		sentry.CaptureException(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response := []models.ListClientsResponse{}
	for _, md := range result {
		response = append(response, models.ListClientsResponse{
			ID:       md.ClientID,
			Name:     md.Name,
			ImageURL: md.ImageUrl,
			URL:      md.URL,
		})
	}
	w.Header().Add("Content-type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		logrus.Error(err)
	}
}

func (svc *service) UpdateClientMetadataHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["clientId"]
	req := &models.CreateClientRequest{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		logrus.Errorf("Error decoding client info request %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("Could not parse create client request"))
		if err != nil {
			logrus.Error(err)
		}
		return
	}

	err = svc.cs.UpdateClient(id, req.Name, req.ImageUrl, req.URL)
	if err != nil {
		logrus.Errorf("Error storing client info %s", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("Something went wrong while storing client info"))
		if err != nil {
			logrus.Error(err)
		}
	}

	w.Header().Add("Content-type", "application/json")
	err = json.NewEncoder(w).Encode(&models.CreateClientResponse{
		ClientId: id,
		Name:     req.Name,
		ImageUrl: req.ImageUrl,
		Url:      req.URL,
	})
	if err != nil {
		logrus.Error(err)
	}
}
func (service *service) FetchClientHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["clientId"]
	result := models.ClientMetaData{}
	err := service.DB.First(&result, &models.ClientMetaData{ClientID: id}).Error
	if err != nil {
		sentry.CaptureException(err)
		status := http.StatusInternalServerError
		if err == gorm.ErrRecordNotFound {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Add("Content-type", "application/json")
	err = json.NewEncoder(w).Encode(&models.ListClientsResponse{
		ID:       result.ClientID,
		Name:     result.Name,
		ImageURL: result.ImageUrl,
		URL:      result.URL,
	})
	if err != nil {
		logrus.Error(err)
	}
}
