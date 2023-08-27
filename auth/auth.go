package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func writeError(res http.ResponseWriter, status int, err string) {
	type Error struct {
		Msg string `json:"error"`
	}

	res.WriteHeader(status)
	encodingErr := writeJson(res, Error{Msg: err})
	if encodingErr != nil {
		slog.Error("could not write error to body", "err", encodingErr)
	}
}

func writeJson(res http.ResponseWriter, body any) error {
	res.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(res).Encode(body)
	if err != nil {
		return fmt.Errorf("could not encode json: %w", err)
	}

	return nil
}

// LoginHandler handles login requests, redirecting the web client to GitHub's
// first stage for the OAuth flow, where the user has to grant access to the specified scopes
func (authenticator *Authenticator) LoginHandler(res http.ResponseWriter, req *http.Request) {

	// Get the client redirect url
	clientRedirectURL := req.URL.Query().Get("redirect_uri")
	if clientRedirectURL == "" {
		writeError(res, http.StatusBadRequest, "specify a redirect_url url param")
		return
	}

	// Create the url query
	query := url.Values{}
	query.Set("redirect_uri", clientRedirectURL)

	// Create the callback url
	redirectCallbackURL := *authenticator.baseURL // Clone the BaseURL so we don't modify it
	redirectCallbackURL.Path = "/login/callback"
	redirectCallbackURL.RawQuery = query.Encode()

	// Create the authorization url
	redirectURL := *GithubAuthorizeURL
	query = redirectURL.Query()
	query.Set("client_id", authenticator.clientID)
	query.Set("redirect_uri", redirectCallbackURL.String())
	query.Set("scope", SCOPES)
	redirectURL.RawQuery = query.Encode()

	// TODO: add the state query parameter to protect against CSRF

	http.Redirect(res, req, redirectURL.String(), http.StatusSeeOther)
}

// GithubAccessTokenRequest is the request we send to GitHub to request for a token
type GithubAccessTokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
}

// GithubAccessTokenResponse is the response received from GitHub when requesting for a token
type GithubAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// CallbackHandler handles the OAuth callback, obtaining the GitHub's Bearer token
// for the logged-in user, and generating a wrapper JWT for our upld session.
func (authenticator *Authenticator) CallbackHandler(res http.ResponseWriter, req *http.Request) {
	// TODO: Check the state query parameter for CSRF attacks

	query := req.URL.Query()
	if query.Has("error") {
		writeError(res, http.StatusInternalServerError, "internal error while parsing the callback")
		slog.Error("error while parsing redirect callback",
			"error", query.Get("error"),
			"description", query.Get("error_description"),
			"uri", query.Get("error_uri"))
		return
	}

	authCode := query.Get("code")
	if authCode == "" {
		writeError(res, http.StatusBadRequest, "missing the code query parameter")
		return
	}

	redirectURI := query.Get("redirect_uri")
	if redirectURI == "" {
		writeError(res, http.StatusBadRequest, "missing the redirect_uri query parameter")
		return
	}

	token, err := authenticator.getToken(authCode)
	if err != nil {
		writeError(res, http.StatusBadRequest, "could not fetch the bearer token from GitHub")
		slog.Error("error while getting the bearer token", "error", err)
		return
	}

	user, err := authenticator.getUser(token)
	if err != nil {
		writeError(res, http.StatusInternalServerError, "could not fetch the user data from GitHub")
		slog.Error("error while fetching user data from github", "error", err)
		return
	}

	iat := time.Now().Add(-1 * time.Minute) // 1 min in the past to allow for clock drift
	exp := iat.Add(authenticator.expiration)
	jwtClaim := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat":   iat.Unix(),
		"exp":   exp.Unix(),
		"token": token,
		"user":  user,
	})
	tokenString, err := jwtClaim.SignedString(authenticator.signingKey)
	if err != nil {
		writeError(res, http.StatusInternalServerError, "could not sign session token")
		return
	}

	cookie := http.Cookie{
		Name:     "auth",
		Value:    tokenString,
		Expires:  time.Now().Add(authenticator.expiration),
		Secure:   false,
		HttpOnly: true,
		Path:     "/",
	}

	http.SetCookie(res, &cookie)
	http.Redirect(res, req, redirectURI, http.StatusSeeOther)
}

// getToken requests GitHub for a token to act on the behalf of a user, provided
// we have received the authentication code for the user. That, is generated after
// the user accepts to log in without OAuth API and gets redirected to our callback.
func (authenticator *Authenticator) getToken(authCode string) (string, error) {
	tokenRequest := GithubAccessTokenRequest{
		ClientId:     authenticator.clientID,
		ClientSecret: authenticator.clientSecret,
		Code:         authCode,
	}

	body, err := json.Marshal(tokenRequest)
	if err != nil {
		return "", fmt.Errorf("could not serialize JSON request: %w", err)
	}

	req, err := http.NewRequest("POST", GithubAccessTokenURL.String(), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("error while constructing the request to GitHub: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error while sending the request to GitHub: %w", err)
	}

	var githubRes GithubAccessTokenResponse
	err = json.NewDecoder(res.Body).Decode(&githubRes)
	if err != nil {
		return "", fmt.Errorf("error while parsing GitHub's response: %w", err)
	}

	return githubRes.AccessToken, nil
}

type GithubUserResponse struct {
	AvatarUrl         string      `json:"avatar_url"`
	Bio               string      `json:"bio"`
	Blog              string      `json:"blog"`
	Collaborators     int         `json:"collaborators"`
	Company           interface{} `json:"company"`
	CreatedAt         time.Time   `json:"created_at"`
	DiskUsage         int         `json:"disk_usage"`
	Email             string      `json:"email"`
	EventsUrl         string      `json:"events_url"`
	Followers         int         `json:"followers"`
	FollowersUrl      string      `json:"followers_url"`
	Following         int         `json:"following"`
	FollowingUrl      string      `json:"following_url"`
	GistsUrl          string      `json:"gists_url"`
	GravatarId        string      `json:"gravatar_id"`
	Hireable          interface{} `json:"hireable"`
	HtmlUrl           string      `json:"html_url"`
	Id                int         `json:"id"`
	Location          string      `json:"location"`
	Login             string      `json:"login"`
	Name              string      `json:"name"`
	NodeId            string      `json:"node_id"`
	OrganizationsUrl  string      `json:"organizations_url"`
	OwnedPrivateRepos int         `json:"owned_private_repos"`
	Plan              struct {
		Collaborators int    `json:"collaborators"`
		Name          string `json:"name"`
		PrivateRepos  int    `json:"private_repos"`
		Space         int    `json:"space"`
	} `json:"plan"`
	PrivateGists            int         `json:"private_gists"`
	PublicGists             int         `json:"public_gists"`
	PublicRepos             int         `json:"public_repos"`
	ReceivedEventsUrl       string      `json:"received_events_url"`
	ReposUrl                string      `json:"repos_url"`
	SiteAdmin               bool        `json:"site_admin"`
	StarredUrl              string      `json:"starred_url"`
	SubscriptionsUrl        string      `json:"subscriptions_url"`
	TotalPrivateRepos       int         `json:"total_private_repos"`
	TwitterUsername         interface{} `json:"twitter_username"`
	TwoFactorAuthentication bool        `json:"two_factor_authentication"`
	Type                    string      `json:"type"`
	UpdatedAt               time.Time   `json:"updated_at"`
	Url                     string      `json:"url"`
}

type User struct {
	Username  string `json:"username"`
	AvatarUrl string `json:"avatarUrl"`
	Name      string `json:"name"`
}

func (authenticator *Authenticator) getUser(token string) (*User, error) {
	req, err := http.NewRequest(http.MethodGet, GithubUserURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not construct GitHub's user request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not send GitHub's user request: %w", err)
	}

	var githubRes GithubUserResponse
	err = json.NewDecoder(res.Body).Decode(&githubRes)
	if err != nil {
		return nil, fmt.Errorf("could not parse GitHub's response: %w", err)
	}

	err = res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("could not close body: %w", err)
	}

	return &User{
		Username:  githubRes.Login,
		AvatarUrl: githubRes.AvatarUrl,
		Name:      githubRes.Name,
	}, nil
}

func (authenticator *Authenticator) WhoAmIHandler(res http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("auth")
	if err != nil {
		writeError(res, http.StatusUnauthorized, "you are not logged in")
		return
	}

	parsedToken, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		return authenticator.signingKey, nil
	})
	if err != nil {
		writeError(res, http.StatusUnauthorized, "invalid token")
		return
	}

	user := parsedToken.Claims.(jwt.MapClaims)["user"]

	err = writeJson(res, user)
	if err != nil {
		writeError(res, http.StatusInternalServerError, "")
		slog.Error("could not encode json:", "error", err)
	}
}
