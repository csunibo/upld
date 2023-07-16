package github

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtTokenConfig struct {
	AppID      string
	KeyPath    string
	Expiration time.Duration
}

// generateJWTToken generates a JWT token for authenticating with
// the GitHub API as a GitHub App. The id is the GitHub App ID.
func generateJWTToken(config *JwtTokenConfig) (string, error) {

	iat := time.Now().Add(-1 * time.Minute) // 1 min in the past to allow for clock drift
	exp := iat.Add(config.Expiration)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": iat.Unix(),
		"exp": exp.Unix(),
		"iss": config.AppID,
		"alg": "RS256",
	})

	key, err := os.ReadFile(config.KeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file: %w", err)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	signedString, err := token.SignedString(privKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedString, nil
}
