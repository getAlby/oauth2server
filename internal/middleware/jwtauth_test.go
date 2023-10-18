package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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
	jwtToken, err := GenerateJWT(secret, Claims{
		ID: &testId,
	})
	assert.NoError(t, err)
	r.Header.Add("Authorization", jwtToken)
	id, err := j.JWTAuth(rec, r)
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", testId), id)
	emtpyToken, err := GenerateJWT(secret, Claims{})
	assert.NoError(t, err)
	r.Header.Set("Authorization", emtpyToken)
	id, err = j.JWTAuth(rec, r)
	assert.Error(t, err)
}
