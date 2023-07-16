package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

func (a *App) AuthenticateAsInstallation(installationId string) (*github.Client, error) {
	const formatUrl = "https://api.github.com/app/installations/%s/access_tokens"
	url := fmt.Sprintf(formatUrl, installationId)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	token := &github.InstallationToken{}
	err = json.NewDecoder(resp.Body).Decode(token)
	if err != nil {
		return nil, err
	}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token.GetToken(),
		TokenType:   "Bearer",
	})

	client := github.NewClient(oauth2.NewClient(context.Background(), tokenSource))
	return client, nil
}
