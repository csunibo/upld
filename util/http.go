package util

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type apiError struct {
	Msg string `json:"error"`
}

func WriteError(res http.ResponseWriter, status int, err string) error {
	res.WriteHeader(status)

	encodingErr := WriteJson(res, apiError{Msg: err})
	if encodingErr != nil {
		return fmt.Errorf("could not write error to body: %w", encodingErr)
	}

	return nil
}

// WriteJson writes the specified body as JSON.
// The body is NOT CLOSED after writing to it.
//
// Returns an error if the write fails.
func WriteJson(res http.ResponseWriter, body any) error {
	res.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(res).Encode(body)
	if err != nil {
		return fmt.Errorf("could not encode json: %w", err)
	}

	return nil
}
