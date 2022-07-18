package smart_on_fhir

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"math/big"
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

	fmt.Println("==> JWKS URI:", epicConfig.JwksURI)

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

	fmt.Println("==> RequestAccessToken Body:", string(b))

	// Unmarshal the body into the `target` struct and return
	target := new(FhirTokenResponse)
	err = json.Unmarshal(b, target)
	if err != nil {
		return nil, err
	}
	return target, nil
}

func buildRSAPublicKey(modulus string, exponent string) (*rsa.PublicKey, error) {
	fmt.Println("===> Modulus:", modulus)
	decodedModulus, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		fmt.Println(err)
		return &rsa.PublicKey{}, err
	}

	bigN := big.NewInt(0)
	bigN.SetBytes(decodedModulus)
	if err != nil {
		fmt.Println(err)
		return &rsa.PublicKey{}, err
	}

	fmt.Println("===> Decoded Modulus:", decodedModulus)
	fmt.Println("===> BigN:", bigN)

	decodedExponent, err := base64.StdEncoding.DecodeString(exponent)
	if err != nil {
		fmt.Println(err)
		return &rsa.PublicKey{}, err
	}

	fmt.Println("===> Exponent:", exponent)
	fmt.Println("===> Decoded Exponent:", decodedExponent)

	var eBytes []byte
	if len(decodedExponent) < 8 {
		eBytes = make([]byte, 8-len(decodedExponent), 8)
		eBytes = append(eBytes, decodedExponent...)
	} else {
		eBytes = decodedExponent
	}

	eReader := bytes.NewReader(eBytes)
	var e uint64
	err = binary.Read(eReader, binary.BigEndian, &e)
	if err != nil {
		fmt.Println(err)
		return &rsa.PublicKey{}, err
	}
	pKey := rsa.PublicKey{N: bigN, E: int(e)}

	fmt.Println("===> Public RSA Key", pKey)

	return &pKey, nil
}
