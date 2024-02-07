package auth

import (
	"net/http"
	"net/url"
	"time"

	"github.com/csunibo/upld/util"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/exp/slog"
)

func (a *Authenticator) WhoAmIHandler(res http.ResponseWriter, req *http.Request) {
	parsedToken, err := a.RequireJWTCookie(res, req)
	if err != nil {
		return
	}

	user := parsedToken.Claims.(jwt.MapClaims)["user"]

	err = util.WriteJson(res, user)
	if err != nil {
		_ = util.WriteError(res, http.StatusInternalServerError, "")
		slog.Error("could not encode json:", "error", err)
	}
}

// CallbackHandler handles the OAuth callback, obtaining the GitHub's Bearer token
// for the logged-in user, and generating a wrapper JWT for our upld session.
func (a *Authenticator) CallbackHandler(res http.ResponseWriter, req *http.Request) {
	// TODO: Check the state query parameter for CSRF attacks

	query := req.URL.Query()
	if query.Has("error") {
		_ = util.WriteError(res, http.StatusInternalServerError, "internal error while parsing the callback")
		slog.Error("error while parsing redirect callback",
			"error", query.Get("error"),
			"description", query.Get("error_description"),
			"uri", query.Get("error_uri"))
		return
	}

	authCode := query.Get("code")
	if authCode == "" {
		_ = util.WriteError(res, http.StatusBadRequest, "missing the code query parameter")
		return
	}

	redirectURI := query.Get("redirect_uri")
	if redirectURI == "" {
		_ = util.WriteError(res, http.StatusBadRequest, "missing the redirect_uri query parameter")
		return
	}

	token, err := a.getToken(authCode)
	if err != nil {
		_ = util.WriteError(res, http.StatusBadRequest, "could not fetch the bearer token from GitHub")
		slog.Error("error while getting the bearer token", "error", err)
		return
	}

	user, err := a.getUser(token)
	if err != nil {
		_ = util.WriteError(res, http.StatusInternalServerError, "could not fetch the user data from GitHub")
		slog.Error("error while fetching user data from github", "error", err)
		return
	}

	iat := time.Now().Add(-1 * time.Minute) // 1 min in the past to allow for clock drift
	exp := iat.Add(a.expiration)

	claims := jwt.MapClaims{
		"iat":   iat.Unix(),
		"exp":   exp.Unix(),
		"token": token,
		"user":  user,
	}

	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.signingKey)
	if err != nil {
		_ = util.WriteError(res, http.StatusInternalServerError, "could not sign session token")
		return
	}

	cookie := http.Cookie{
		Name:     "auth",
		Value:    tokenString,
		Expires:  time.Now().Add(a.expiration),
		Secure:   false,
		HttpOnly: true,
		Path:     "/",
	}

	http.SetCookie(res, &cookie)
	http.Redirect(res, req, redirectURI, http.StatusSeeOther)
}

// LoginHandler handles login requests, redirecting the web client to GitHub's
// first stage for the OAuth flow, where the user has to grant access to the specified scopes
func (a *Authenticator) LoginHandler(res http.ResponseWriter, req *http.Request) {

	// Get the client redirect url
	clientRedirectURL := req.URL.Query().Get("redirect_uri")
	if clientRedirectURL == "" {
		_ = util.WriteError(res, http.StatusBadRequest, "specify a redirect_uri url param")
		return
	}

	// Create the url query
	query := url.Values{}
	query.Set("redirect_uri", clientRedirectURL)

	// Create the callback url
	redirectCallbackURL := *a.baseURL // Clone the BaseURL so we don't modify it
	redirectCallbackURL.Path = "/login/callback"
	redirectCallbackURL.RawQuery = query.Encode()

	// Create the authorization url
	redirectURL := *GithubAuthorizeURL
	query = redirectURL.Query()
	query.Set("client_id", a.clientID)
	query.Set("redirect_uri", redirectCallbackURL.String())
	query.Set("scope", SCOPES)
	redirectURL.RawQuery = query.Encode()

	// TODO: add the state query parameter to protect against CSRF

	http.Redirect(res, req, redirectURL.String(), http.StatusSeeOther)
}
