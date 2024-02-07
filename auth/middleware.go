package auth

import (
	"net/http"

	"github.com/csunibo/upld/util"
	"github.com/golang-jwt/jwt/v5"
)

func (a *Authenticator) RequireJWTCookie(w http.ResponseWriter, r *http.Request) (*jwt.Token, error) {
	cookie, err := r.Cookie("auth")
	if err != nil {
		_ = util.WriteError(w, http.StatusUnauthorized, "you are not logged in")
		return nil, err
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		return a.signingKey, nil
	}

	parsedToken, err := jwt.Parse(cookie.Value, keyFunc)
	if err != nil {
		_ = util.WriteError(w, http.StatusUnauthorized, "invalid token")
		return nil, err
	}

	return parsedToken, nil
}
