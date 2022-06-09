package smart_on_fhir

import (
	"golang.org/x/oauth2"
)

// Provider is a struct wrapping the necessary bits to integrate an OAuth2 provider with AuthN
type FhirProvider struct {
	config   *oauth2.Config
	UserInfo UserInfoFetcher
}

// UserInfo is the minimum necessary needed from an OAuth Provider to connect with AuthN accounts
type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// Add additional information to the token response
type FhirTokenResponse struct {
	AccessToken   string `json:"access_token"`
	IdToken       string `json:"id_token"`
	Scope         string `json:"scope"`
	Encounter     string `json:"encounter"`
	PatientFhirId string `json:"patient"`
}

// UserInfoFetcher is the function signature for fetching UserInfo from a Provider
type UserInfoFetcher = func(t *FhirTokenResponse) (*UserInfo, error)

// Config returns a complete oauth2.Config after injecting the RedirectURL
func (p *FhirProvider) Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Scopes:       p.config.Scopes,
		Endpoint:     p.config.Endpoint,
		RedirectURL:  redirectURL,
	}
}

func (p *FhirProvider) TokenUrl() string {
	return p.config.Endpoint.TokenURL
}

func (p *FhirProvider) ClientID() string {
	return p.config.ClientID
}

func (p *FhirProvider) ClientSecret() string {
	return p.config.ClientSecret
}
