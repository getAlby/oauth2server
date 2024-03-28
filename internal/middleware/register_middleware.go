package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/felixge/httpsnoop"
	sentryhttp "github.com/getsentry/sentry-go/http"
	"github.com/gorilla/handlers"
	"github.com/sirupsen/logrus"
)

// panic recover, logging, Sentry middlewares
func RegisterMiddleware(h http.Handler) http.Handler {
	h = handlers.RecoveryHandler()(h)
	h = LoggingMiddleware(h)
	h = sentryhttp.New(sentryhttp.Options{}).Handle(h)
	return h
}

type TokenKey string
const TOKEN_INFO_KEY TokenKey = "token_info"

type LogTokenInfo struct {
	UserId   string
	ClientId string
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		entry := logrus.NewEntry(logrus.StandardLogger())
		entry = entry.WithField("host", r.Host)
		entry = entry.WithField("id", r.Header.Get("X-Request-Id"))
		remoteIpList := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if len(remoteIpList) > 0 {
			entry = entry.WithField("remote_ip", remoteIpList[0])
		}
		entry = entry.WithField("connecting_ip", r.Header.Get("CF-Connecting-IP"))
		entry = entry.WithField("country_code", r.Header.Get("CF-IPCountry"))
		entry = entry.WithField("referer", r.Referer())
		entry = entry.WithField("user_agent", r.UserAgent())
		entry = entry.WithField("x_user_agent", r.Header.Get("X-User-Agent"))
		entry = entry.WithField("uri", r.URL.Path)
		lti := &LogTokenInfo{}
		r = r.WithContext(context.WithValue(r.Context(), TOKEN_INFO_KEY, lti))
		//this already calls next.ServeHttp
		m := httpsnoop.CaptureMetrics(next, w, r)
		entry = entry.WithField("latency", m.Duration.Seconds())
		entry = entry.WithField("status", m.Code)
		entry = entry.WithField("bytes_out", m.Written)
		tokenInfo := r.Context().Value(TOKEN_INFO_KEY)
		if tokenInfo != nil {
			logTokenInfo := tokenInfo.(*LogTokenInfo)
			entry = entry.WithField("user_id", logTokenInfo.UserId)
			entry = entry.WithField("client_id", logTokenInfo.ClientId)
		}
		entry.Info()
	})
}
