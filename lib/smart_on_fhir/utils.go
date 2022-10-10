package smart_on_fhir

import (
	"encoding/json"
	"io"
	"net/http"
)

func discoverAuthServer(issuer string, target interface{}) error {
	resp, err := http.Get(issuer + "/.well-known/smart-configuration")
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return json.Unmarshal(b, target)
}

func fetchEpicJWKS() (*EpicJwksResponse, error) {
	client := http.Client{}
	req, _ := http.NewRequest("GET", "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/.well-known/openid-configuration", nil)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	epicConfig := new(OpenIDConfiguration)
	json.Unmarshal(body, epicConfig)

	jwksReq, _ := http.NewRequest("GET", epicConfig.JwksURI, nil)
	jwksReq.Header.Add("Content-Type", "application/json")

	jwksResp, err := client.Do(jwksReq)
	if err != nil {
		return nil, err
	}
	defer jwksResp.Body.Close()

	epicJwksResponse := new(EpicJwksResponse)
	jwksBody, err := io.ReadAll(jwksResp.Body)
	json.Unmarshal(jwksBody, epicJwksResponse)

	return epicJwksResponse, err
}
