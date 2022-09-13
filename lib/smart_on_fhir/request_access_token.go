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

func RequestAccessToken(tokenUrl string, clientId string, clientSecret string, code string) (*FhirTokenResponse, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	// Set the form data for the request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:21001/fhir/epic/return")
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret)

	encodedBody := data.Encode()

	// Create the request
	req, err := http.NewRequest("POST", tokenUrl, strings.NewReader(encodedBody))
	if err != nil {
		return nil, fmt.Errorf("got error %s", err.Error())
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Read the body
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	// Unmarshal the body into the `target` struct and return
	target := new(FhirTokenResponse)
	err = json.Unmarshal(b, target)
	if err != nil {
		return nil, err
	}
	return target, nil
}
