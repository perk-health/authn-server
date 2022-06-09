package smart_on_fhir

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
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

func RequestAccessToken(tokenUrl string, clientId string, clientSecret string, code string) (*FhirTokenResponse, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	// Set the form data for the request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:21001/fhir/epic/return/provider")
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)
	encodedBody := data.Encode()

	// Create the request
	req, err := http.NewRequest("POST", tokenUrl, strings.NewReader(encodedBody))
	if err != nil {
		return nil, fmt.Errorf("Got error %s", err.Error())
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	resp, err := client.Do(req)

	// Read the body
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)

	fmt.Println("RequestAccessToken Body:", string(b))

	// Unmarshal the body into the `target` struct and return
	target := new(FhirTokenResponse)
	err = json.Unmarshal(b, target)
	if err != nil {
		return nil, err
	}
	return target, nil
}
