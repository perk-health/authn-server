package handlers

import (
	"encoding/json"
	"io"
	"net/http"
)

type ehrAuthMetadata struct {
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
}

func discoverAuthServer(issuer string, target interface{}) error {
	resp, err := http.Get(issuer + "/.well-known/smart-configuration")

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)

	return json.Unmarshal(b, target)
}
