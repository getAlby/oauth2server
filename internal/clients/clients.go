package clients

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	oauth2gorm "github.com/getAlby/go-oauth2-gorm"
	"github.com/getsentry/sentry-go"
	"github.com/go-playground/validator"
	"gorm.io/gorm"

	"github.com/gorilla/mux"
	"github.com/labstack/gommon/random"
	"github.com/sirupsen/logrus"
)

const (
	ClientIdLength     = 10
	ClientSecretLength = 20
)

var CONTEXT_ID_KEY string = "ID"

type Service struct {
	cs     ClientStore
	scopes map[string]string
}

type ClientStore interface {
	Create(ctx context.Context, id, secret, domain, url, imageUrl, name string) error
	ListAllClients() (result []ClientMetaData, err error)
	UpdateClient(clientId, name, imageUrl, url string) (err error)
	GetClient(clientId string) (result *ClientMetaData, err error)
	GetTokensForUser(userId string) (result []oauth2gorm.TokenStoreItem, err error)
	DeleteClient(clientId string) error
}

func NewService(cs ClientStore, scopes map[string]string) *Service {
	return &Service{
		cs:     cs,
		scopes: scopes,
	}
}

func RegisterRoutes(adminRouter, userRouter *mux.Router, svc *Service) {
	//these routes should not be publicly accesible
	adminRouter.HandleFunc("/admin/clients", svc.CreateClientHandler).Methods(http.MethodPost)
	adminRouter.HandleFunc("/admin/clients", svc.ListAllClientsHandler).Methods(http.MethodGet)
	adminRouter.HandleFunc("/admin/clients/{clientId}", svc.FetchClientHandler).Methods(http.MethodGet)
	adminRouter.HandleFunc("/admin/clients/{clientId}", svc.UpdateClientMetadataHandler).Methods(http.MethodPut)

	userRouter.HandleFunc("/clients", svc.ListClientsForUserandler).Methods(http.MethodGet)
	userRouter.HandleFunc("/clients/{clientId}", svc.UpdateClientHandler).Methods(http.MethodPost)
	userRouter.HandleFunc("/clients/{clientId}", svc.DeleteClientHandler).Methods(http.MethodDelete)

}

func (svc *Service) CreateClientHandler(w http.ResponseWriter, r *http.Request) {
	req := &CreateClientRequest{}
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
	id := random.New().String(ClientIdLength)
	var secret string
	if !req.Public {
		secret = random.New().String(ClientSecretLength)
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
	err = json.NewEncoder(w).Encode(&CreateClientResponse{
		Name:         req.Name,
		ImageUrl:     req.ImageUrl,
		ClientId:     id,
		ClientSecret: secret,
	})
	if err != nil {
		logrus.Error(err)
	}
}

func (svc *Service) ListAllClientsHandler(w http.ResponseWriter, r *http.Request) {
	result, err := svc.cs.ListAllClients()
	if err != nil {
		sentry.CaptureException(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response := []ListClientsResponse{}
	for _, md := range result {
		response = append(response, ListClientsResponse{
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
func (svc *Service) ListClientsForUserandler(w http.ResponseWriter, r *http.Request) {
	userId := r.Context().Value(CONTEXT_ID_KEY)
	result, err := svc.cs.GetTokensForUser(userId.(string))
	if err != nil {
		sentry.CaptureException(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response := []ListClientsResponse{}
	for _, ti := range result {
		//todo: more efficient queries ?
		//store information in a single relation when a token is created?
		data, err := svc.cs.GetClient(ti.ClientID)
		if err != nil {
			sentry.CaptureException(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		parsed, _ := url.Parse(ti.RedirectURI)
		scopes := map[string]string{}
		for _, sc := range strings.Split(ti.Scope, " ") {
			scopes[sc] = svc.scopes[sc]
		}
		response = append(response, ListClientsResponse{
			Domain:   parsed.Host,
			ID:       ti.ClientID,
			Name:     data.Name,
			ImageURL: data.ImageUrl,
			URL:      data.URL,
			Scopes:   scopes,
		})
	}
	w.Header().Add("Content-type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		logrus.Error(err)
	}
}

func (svc *Service) UpdateClientMetadataHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["clientId"]
	req := &CreateClientRequest{}
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
	err = json.NewEncoder(w).Encode(&CreateClientResponse{
		ClientId: id,
		Name:     req.Name,
		ImageUrl: req.ImageUrl,
		Url:      req.URL,
	})
	if err != nil {
		logrus.Error(err)
	}
}
func (service *Service) FetchClientHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["clientId"]
	result, err := service.cs.GetClient(id)
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
	err = json.NewEncoder(w).Encode(&ListClientsResponse{
		ID:       result.ClientID,
		Name:     result.Name,
		ImageURL: result.ImageUrl,
		URL:      result.URL,
	})
	if err != nil {
		logrus.Error(err)
	}
}

// should be used for budgets later
func (svc *Service) UpdateClientHandler(w http.ResponseWriter, r *http.Request) {
}

// deletes all tokens a user currently has for a given client
func (svc *Service) DeleteClientHandler(w http.ResponseWriter, r *http.Request) {
	clientId := mux.Vars(r)["clientId"]
	err := svc.cs.DeleteClient(clientId)
	if err != nil {
		sentry.CaptureException(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
