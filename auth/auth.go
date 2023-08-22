package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/exp/slog"
)

const (
	SCOPES = "read:user,user:email"
)

var (
	maxState = big.NewInt(math.MaxInt64)

	GithubClientID     *string
	GithubClientSecret *string

	GithubAuthorizeURL, _   = url.Parse("https://github.com/login/oauth/authorize")
	GithubAccessTokenURL, _ = url.Parse("https://github.com/login/oauth/access_token")
	GithubUserURL, _        = url.Parse("https://api.github.com/user")
)

type GithubData struct {
	payload    string
	authorized bool
}

type Authenticator struct {
	clientID     string
	clientSecret string
	baseURL      *url.URL
	expiration   time.Duration
	signingKey   []byte
}

type Config struct {
	// The OAuth client ID
	ClientID string
	// The OAuth client secret
	ClientSecret string
	// The base URL from where csunibo/upld is being served from
	BaseURL *url.URL
	// The key to sign the JWTs with
	SigningKey []byte
	// How long should user sessions last?
	Expiration time.Duration
}

func NewAuthenticator(config *Config) *Authenticator {
	authenticator := Authenticator{
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		baseURL:      config.BaseURL,
		signingKey:   config.SigningKey,
		expiration:   config.Expiration,
	}
	return &authenticator
}

func writeError(res http.ResponseWriter, status int, err error) error {
	res.WriteHeader(status)
	type Error struct {
		Message string `json:"message"`
	}

	bytes, err := json.Marshal(Error{
		Message: err.Error(),
	})
	if err != nil {
		return err
	}

	if w, err := res.Write(bytes); err != nil || w != len(bytes) {
		return fmt.Errorf("Could not write HTTP response: %w, wrote %d out of %d byes", err, w, len(bytes))
	}

	return nil
}

// LoginHandler handles login requests, redirecting the web client to GitHub's
// first stage for the OAuth flow, where the user has to grant access to the specified scopes
func (authenticator *Authenticator) LoginHandler(res http.ResponseWriter, req *http.Request) {
	redirectCallbackURL := *authenticator.baseURL // Clone the BaseURL so we don't modify it
	redirectCallbackURL.Path = "/login/callback"

	redirectURL := *GithubAuthorizeURL
	redirectURL.Query().Add("client_id", authenticator.clientID)
	redirectURL.Query().Add("redirect_uri", url.QueryEscape(redirectCallbackURL.String()))
	redirectURL.Query().Add("scope", SCOPES)
	// TODO: add the state query parameter to protect against CSRF

	http.Redirect(res, req, redirectURL.String(), http.StatusTemporaryRedirect)
}

// The request we send to Github to request for a token
type GithubAccessTokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
}

// The response received from Github when requesting for a token
type GithubAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// CallbackHandler handles the OAuth callback, obtaining the GitHub's Bearer token
// for the logged-in user, and generating a wrapper JWT for our upld session.
func (authenticator *Authenticator) CallbackHandler(res http.ResponseWriter, req *http.Request) {
	// TODO: Check the state query parameter for CSRF attacks

	authCode := req.URL.Query().Get("code")
	if authCode == "" {
		if err := writeError(res, http.StatusBadRequest, errors.New("Missing the code query parameter")); err != nil {
			slog.Error("Could not report the error back to the user", "err", err)
		}
	}

	token, err := authenticator.getToken(authCode)
	if err != nil {
		if err := writeError(res, http.StatusBadRequest, errors.New("Could not fetch the bearer token from GitHub")); err != nil {
			slog.Error("Could not report the error back to the user", "err", err)
		}
	}

	user, err := authenticator.getUser(token)
	if err != nil {
		if err := writeError(res, http.StatusBadRequest, errors.New("Could not fetch the user data from GitHub")); err != nil {
			slog.Error("Could not report the error back to the user", "err", err)
		}
	}

	iat := time.Now().Add(-1 * time.Minute) // 1 min in the past to allow for clock drift
	exp := iat.Add(authenticator.expiration)
	jwt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat":   iat.Unix(),
		"exp":   exp.Unix(),
		"token": token,
		"user":  user,
	})
	tokenString, err := jwt.SignedString(authenticator.signingKey)
	if err != nil {
		if err := writeError(res, http.StatusInternalServerError, fmt.Errorf("Could not sign session token: %w", err)); err != nil {
			slog.Error("Could not report the error back to the user", "err", err)
		}
	}

	cookie := http.Cookie{}
	cookie.Name = "auth"
	cookie.Value = tokenString
	cookie.Expires = time.Now().Add(authenticator.expiration)
	cookie.Secure = false
	cookie.HttpOnly = true
	cookie.Path = "/"
	http.SetCookie(res, &cookie)
}

// getToken requests GitHub for a token to act on the behalf of a user, provided
// we have received the authentication code for the user. That, is generated after
// the user accepts to log-in with out OAuth API and gets redirected to our callback.
func (authenticator *Authenticator) getToken(authCode string) (string, error) {
	requestBody := GithubAccessTokenRequest{
		ClientId:     *GithubClientID,
		ClientSecret: *GithubClientSecret,
		Code:         authCode,
	}
	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("Could not serialize JSON request: %v", err)
	}

	req, err := http.NewRequest(
		"POST",
		GithubAccessTokenURL.String(),
		bytes.NewBuffer(requestJSON),
	)
	if err != nil {
		return "", fmt.Errorf("Error while constructing the request to GitHub: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, resErr := http.DefaultClient.Do(req)
	if resErr != nil {
		return "", fmt.Errorf("Error while sending the request to GitHub: %w", err)
	}

	var githubRes GithubAccessTokenResponse
	err = json.NewDecoder(res.Body).Decode(&githubRes)
	if err != nil {
		return "", fmt.Errorf("Error while parsing GitHub's response: %w", err)
	}

	return githubRes.AccessToken, nil
}

type GithubUserResponse struct {
	Login     string   `json:"login"`
	AvatarURL *url.URL `json:"avatar_url"`
	Name      string   `json:"name"`
}

type User struct {
	Username string   `json:"username"`
	Propic   *url.URL `json:"propic"`
	Name     string   `json:"name"`
}

func (authenticator *Authenticator) getUser(token string) (*User, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		GithubUserURL.String(),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("Could not construct GitHub's user request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Could not send GitHub's user request: %w", err)
	}

	var githubRes GithubUserResponse
	err = json.NewDecoder(res.Body).Decode(&githubRes)
	if err != nil {
		return nil, fmt.Errorf("Error while parsing GitHub's response: %w", err)
	}

	user := User{
		Username: githubRes.Login,
		Propic:   githubRes.AvatarURL,
		Name:     githubRes.Name,
	}
	return &user, nil
}

func (authenticator *Authenticator) WhoamiHandler(res http.ResponseWriter, req *http.Request) {
}
