package main

import (
	"context"
	"os"

	"github.com/google/go-github/github"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"

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
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.ErrorMarshalFunc = pkgerrors.MarshalStack

	var err error
	config, err = loadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	if err := intern(); err != nil {
		log.Fatal().Stack().Err(err).Msg("error")
	}
}

func intern() error {
	var err error
	client, err = initializeClient()
	if err != nil {
		return err
	}

	// TODO: From here it's all testing code
	repositories, _, err := client.Repositories.List(context.Background(), "csunibo", nil)
	if err != nil {
		return err
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
		return err
	}

	println(comment.URL)

	return nil
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
	open, err := os.Open("config.toml")
	if err != nil {
		return nil, err
	}

	err = toml.NewDecoder(open).Decode(&config)
	if err != nil {
		return nil, err
	}

	err = open.Close()
	if err != nil {
		return nil, err
	}

	return config, nil
}
