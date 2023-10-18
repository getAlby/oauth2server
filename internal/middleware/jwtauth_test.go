package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

func TestJWTAuth(t *testing.T) {
	secret := []byte("SECRET")
	testId := int64(123)
	j, err := NewJWTAuth(secret)
	assert.NoError(t, err)
	rec := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.NoError(t, err)
	jwtToken, err := generateLNDHubAccessToken(secret, claims{
		ID: &testId,
	})
	assert.NoError(t, err)
	r.Header.Add("Authorization", jwtToken)
	id, err := j.JWTAuth(rec, r)
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", testId), id)
	emtpyToken, err := generateLNDHubAccessToken(secret, claims{})
	assert.NoError(t, err)
	r.Header.Set("Authorization", emtpyToken)
	id, err = j.JWTAuth(rec, r)
	assert.Error(t, err)
}

// GenerateAccessToken : Generate Access Token
func generateLNDHubAccessToken(secret []byte, claims claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return t, nil
}

type claims struct {
	ID        *int64 `json:"id"`
	IsRefresh bool   `json:"isRefresh"`
	ClientId  string `json:"clientId"`
	jwt.StandardClaims
}
