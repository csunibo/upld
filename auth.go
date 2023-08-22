// Inspired by https://sharmarajdaksh.github.io/blog/github-oauth-with-go

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type GithubData struct {
	payload    string
	authorized bool
}

// Represents the request we send to Github
type GithubAccessTokenRequest struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
}

// Represents the response received from Github
type GithubAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

func getGithubAccessToken(code string) (string, error) {
	githubClientID, exists := os.LookupEnv("CLIENT_ID")

	if !exists {
		return "", errors.New("Github client id not existing")
	}

	githubClientSecret, exists := os.LookupEnv("CLIENT_SECRET")
	if !exists {
		return "", errors.New("Github client secret not existing")
	}

	requestBody := GithubAccessTokenRequest{
		ClientId:     githubClientID,
		ClientSecret: githubClientSecret,
		Code:         code,
	}
	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("Could not serialize JSON request: %v", err)
	}

	req, err := http.NewRequest(
		"POST",
		"https://github.com/login/oauth/access_token",
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

func githubLoginHandler(writer http.ResponseWriter, req *http.Request) {
	log.Println("New login request")

	githubClientID, idErr := getGithubClientID()
	if idErr != nil {
		log.Fatalln(idErr.Error())
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	redirectUrl := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s",
		githubClientID,
		"/login/callback", //TODO: using the entire url???
	)

	log.Println("Redirecting to redirect url")
	http.Redirect(writer, req, redirectUrl, http.StatusMovedPermanently)
}

func getGithubData(accessToken string) (string, error) {
	req, reqErr := http.NewRequest(
		http.MethodGet,
		"https://api.github.com/user",
		nil,
	)
	if reqErr != nil {
		return "", reqErr
	}

	authorizationHeaderValue := fmt.Sprintf("token %s", accessToken)
	req.Header.Set("Authorization", authorizationHeaderValue)

	res, resErr := http.DefaultClient.Do(req)
	if resErr != nil {
		return "", resErr
	}

	resbody, _ := ioutil.ReadAll(res.Body)

	return string(resbody), nil
}

func loggedinHandler(
	writer http.ResponseWriter,
	req *http.Request,
	githubData GithubData,
) {
	if !githubData.authorized {
		log.Println("User unauthorized")
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.Println("User authorized")

	writer.Header().Set("Content-type", "application/json")

	// Prettifying the json
	var prettyJSON bytes.Buffer
	parseErr := json.Indent(&prettyJSON, []byte(githubData.payload), "", "\t")
	if parseErr != nil {
		log.Fatalln(parseErr.Error())
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Println("Sending github data")
	fmt.Fprintf(writer, string(prettyJSON.Bytes()))
}

func unauthorizedUserHandler(writer http.ResponseWriter, req *http.Request) {
	loggedinHandler(writer, req, GithubData{payload: "", authorized: false})
}

func githubCallbackHandler(writer http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get("code")

	githubAccessToken, tokenErr := getGithubAccessToken(code)
	if tokenErr != nil {
		log.Fatalln(tokenErr.Error())
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	githubData, dataErr := getGithubData(githubAccessToken)
	if dataErr != nil {
		log.Fatalln(dataErr.Error())
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	loggedinHandler(writer, req, GithubData{
		payload:    githubData,
		authorized: true,
	})
}
