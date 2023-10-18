package middleware

import (
	"context"
	"fmt"
	"net/http"

	"github.com/getsentry/sentry-go"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
)

type JWTAuth struct {
	JWTSecret []byte
}

// JWTAuth authenticates the user directly against a JWT token
// present in the request instead of reaching auth to LNDhub
func NewJWTAuth(secret []byte) (JWTAuth, error) {
	result := JWTAuth{
		JWTSecret: secret,
	}

	return result, nil
}

func (j JWTAuth) JWTAuth(w http.ResponseWriter, r *http.Request) (userID string, err error) {

	token := r.Header.Get("Authorization")
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return j.JWTSecret, nil
	})
	if err != nil {
		return "", err
	}
	if claims["id"] == nil {
		return "", fmt.Errorf("Cannot authenticate user, token does not contain user id")
	}
	return fmt.Sprintf("%.0f", claims["id"].(float64)), nil
}

func (j JWTAuth) UserAuthorizeMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := j.JWTAuth(w, r)
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

func GenerateJWT(secret []byte, claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return t, nil
}

type Claims struct {
	ID        *int64 `json:"id"`
	IsRefresh bool   `json:"isRefresh"`
	ClientId  string `json:"clientId"`
	jwt.StandardClaims
}
