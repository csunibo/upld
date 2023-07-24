package main

import (
	"context"
	"os"

	"github.com/google/go-github/github"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/exp/slog"

	csunibo "github.com/csunibo/upld/github"
)

type Config struct {
	AppID          string `toml:"app_id" required:"true"`
	InstallationID string `toml:"installation_id" required:"true"`
	PrivateKeyPath string `toml:"private_key_path" required:"true"`
}

var (
	config *Config
	client *github.Client
)

func main() {

	var err error
	config, err = loadConfig()
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	client, err = initializeClient()
	if err != nil {
		slog.Error("failed to initialize client", "err", err)
		os.Exit(1)
	}

	// TODO: From here it's all testing code
	repositories, _, err := client.Repositories.List(context.Background(), "csunibo", nil)
	if err != nil {
		slog.Error("failed to list repositories", "err", err)
		os.Exit(1)
	}

	for _, repository := range repositories {
		println(repository.GetName())
	}

	comment, _, err := client.Issues.CreateComment(
		context.Background(),
		"csunibo",
		"ing-sistemi-informativi-test",
		1,
		&github.IssueComment{
			Body: github.String("Hello, world!"),
		})
	if err != nil {
		slog.Error("failed to create comment", "err", err)
		os.Exit(1)
	}

	slog.Info("comment created", "id", comment.GetID(), "url", comment.GetURL())
}

func initializeClient() (*github.Client, error) {
	app, err := csunibo.NewApp(&csunibo.AppConfig{
		AppID:   config.AppID,
		KeyPath: config.PrivateKeyPath,
	})
	if err != nil {
		return nil, err
	}

	return app.AuthenticateAsInstallation(config.InstallationID)
}

func loadConfig() (config *Config, err error) {
	file, err := os.Open("config.toml")
	if err != nil {
		return nil, err
	}

	err = toml.NewDecoder(file).Decode(&config)
	if err != nil {
		return nil, err
	}

	err = file.Close()
	if err != nil {
		return nil, err
	}

	return config, nil
}
