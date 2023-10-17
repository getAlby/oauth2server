package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/getsentry/sentry-go"
	"github.com/sirupsen/logrus"
)

type MockAuth struct {
}

const testUserId = "12345"
const testUserLogin = "login"
const testUserPassword = "password"

func NewMockAuth() (MockAuth, error) {
	result := MockAuth{}

	return result, nil
}

func (l MockAuth) MockAuth(w http.ResponseWriter, r *http.Request) (userID string, err error) {
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
	if !(login == testUserLogin && password == testUserPassword) {
		return "", fmt.Errorf("mock auth: cannot authenticate user, login or password wrong.")
	}
	return testUserId, nil
}

func (l MockAuth) UserAuthorizeMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := l.MockAuth(w, r)
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
