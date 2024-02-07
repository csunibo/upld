package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/csunibo/upld/util"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/exp/slog"
)

var (
	GithubApiURL, _ = url.Parse("https://api.github.com/")
)

type Committer struct {
	Name  string `json:name`
	Email string `json:email`
}

type GithubFileUpld struct {
	Owner     string    `json:"owner`
	Repo      string    `json:"reoo`
	Path      string    `json:"path`
	Message   string    `json:"message`
	Committer Committer `json:"committer`
	Content   string    `json:"content`
}

func (a *Authenticator) UpldFile(res http.ResponseWriter, req *http.Request) {
	parsedToken, err := a.RequireJWTCookie(res, req)
	if err != nil {
		return
	}

	user := parsedToken.Claims.(jwt.MapClaims)["user"].(string)
	usr, err := a.getUser(user)
	if err != nil {
		return
	}

	var data GithubFileUpld
	err = json.NewDecoder(req.Body).Decode(&data)
	if err != nil {
		return
	}

	data.Committer = Committer{
		Name:  usr.Name,
		Email: usr.Email,
	}

	body, err := json.Marshal(data)
	if err != nil {
		return
	}

	// PUT {apiurl}/repos/{owner}/{repo}/contents/{path}
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", GithubApiURL.String(), data.Owner, data.Repo, data.Path)
	gitreq, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return
	}

	gitres, err := client.Do(gitreq)
	if err != nil {
		return
	}

	err = util.WriteJson(res, gitres)
	if err != nil {
		_ = util.WriteError(res, http.StatusInternalServerError, "")
		slog.Error("could not encode json:", "error", err)
	}
}
