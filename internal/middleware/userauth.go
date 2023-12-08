package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/getsentry/sentry-go"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
)

var CONTEXT_ID_KEY string = "ID"

type LNDHubUserAuth struct {
	JWTSecret []byte
	LNDHubURL string
}

func NewLNDHubUserAuth(secret []byte, url string) (LNDHubUserAuth, error) {
	result := LNDHubUserAuth{
		JWTSecret: secret,
		LNDHubURL: url,
	}

	return result, nil
}

func (l LNDHubUserAuth) LNDHubUserAuth(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	token, err := authenticateUser(r, l.LNDHubURL)
	if err != nil {
		logrus.Error(err)
		sentry.CaptureException(err)
		return "", err
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return l.JWTSecret, nil
	})
	if err != nil {
		return "", err
	}
	if claims["id"] == nil {
		return "", fmt.Errorf("Cannot authenticate user, token does not contain user id")
	}
	return fmt.Sprintf("%.0f", claims["id"].(float64)), nil
}

func (l LNDHubUserAuth) UserAuthorizeMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := l.LNDHubUserAuth(w, r)
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

func authenticateUser(r *http.Request, lndhubUrl string) (token string, err error) {
	err = r.ParseForm()
	//look for login/password in form data
	//but also allow basic auth, form data only works with POST requests
	login, password, ok := r.BasicAuth()
	if ok {
		r.Form.Add("login", login)
		r.Form.Add("password", password)
	}
	if err != nil {
		return "", fmt.Errorf("Error parsing form data %s", err.Error())
	}
	login = r.Form.Get("login")
	password = r.Form.Get("password")

	if login == "" && password == "" {
		return "", fmt.Errorf("Cannot authenticate user, form data missing.")
	}

	if login == "" || password == "" {
		return "", fmt.Errorf("Cannot authenticate user, login or password missing.")
	}
	//authenticate user against lndhub
	resp, err := http.PostForm(fmt.Sprintf("%s/auth", lndhubUrl), r.Form)
	if err != nil {
		logrus.WithField("login", login).Errorf("Cannot authenticate user. post failed (login: %s error: %v )", login, err.Error())
		return "", fmt.Errorf("Error authenticating user %s", err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		logrus.WithField("login", login).Errorf("Cannot authenticate user, login or password wrong. (login: %s status: %v)", login, resp.StatusCode)
		return "", fmt.Errorf("Cannot authenticate user, login or password wrong. (login: %s)", login)
	}
	//return access code
	tokenResponse := &LNDHubTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(tokenResponse)
	if err != nil {
		return "", fmt.Errorf("Error authenticating user %s", err.Error())
	}
	return tokenResponse.AccessToken, nil
}

type LNDHubTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}
