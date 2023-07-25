package github

import (
	"fmt"
	"net/http"
	"time"
)

const tokenDuration = time.Minute * 5

type AppConfig struct {
	AppID   string
	KeyPath string
}

type App struct {
	jwt       string
	createdAt time.Time
	config    *AppConfig
}

// NewApp authenticates as a GitHub App.
//
// https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app
func NewApp(config *AppConfig) (*App, error) {
	signedToken, err := generateJWTToken(&JwtTokenConfig{
		AppID:      config.AppID,
		KeyPath:    config.KeyPath,
		Expiration: tokenDuration,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT token: %w", err)
	}

	return &App{
		jwt:       signedToken,
		createdAt: time.Now(),
		config:    config,
	}, nil
}

func (a *App) Do(request *http.Request) (*http.Response, error) {
	if time.Since(a.createdAt) > tokenDuration {
		newApp, err := NewApp(a.config)
		if err != nil {
			return nil, fmt.Errorf("failed to refresh JWT token: %w", err)
		}
		*a = *newApp
	}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.jwt))
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	return http.DefaultClient.Do(request)
}
