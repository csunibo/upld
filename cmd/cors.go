package main

import (
	"net/http"

	"golang.org/x/exp/slices"
)

type CorsMiddleware struct {
	handler          http.Handler
	origin           []string
	allowCredentials bool
}

func (c CorsMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if c.origin != nil && slices.Contains(c.origin, r.Host) {
		w.Header().Set("Access-Control-Allow-Origin", r.Host)
	}
	if c.allowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	c.handler.ServeHTTP(w, r)
}

func NewCors(origin []string, allowCredentials bool, handler http.Handler) *CorsMiddleware {
	return &CorsMiddleware{handler: handler, origin: origin, allowCredentials: allowCredentials}
}
