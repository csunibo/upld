package main

import (
	"golang.org/x/exp/slices"
	"net/http"
)

type Adapter func(http.Handler) http.Handler
type Middleware func(h http.Handler, w http.ResponseWriter, r *http.Request)

func Adapt(middleware Middleware) Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			middleware(h, w, r)
		})
	}
}

type CorsConfig struct {
	Origin           []string
	AllowCredentials bool
}

// CorsHeader creates a middleware that applies a CORS policy with the specified origin.
func CorsHeader(config CorsConfig) Adapter {
	return Adapt(func(h http.Handler, w http.ResponseWriter, r *http.Request) {
		if config.Origin != nil && slices.Contains(config.Origin, r.Host) {
			w.Header().Set("Access-Control-Allow-Origin", r.Host)
		}
		if config.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		h.ServeHTTP(w, r)
	})
}
