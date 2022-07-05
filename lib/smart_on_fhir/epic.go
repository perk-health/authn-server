package smart_on_fhir

import (
	"encoding/json"
	"fmt"

	"github.com/cristalhq/jwt/v4"
	"golang.org/x/oauth2"
)

func NewEpicSmartOnFhirProvider(credentials *Credentials) *FhirProvider {
	// urlValues := url.Values{}
	// urlValues.Set("launch", someLaunchCode)

	config := &oauth2.Config{
		ClientID:     credentials.ID,
		ClientSecret: credentials.Secret,
		Scopes: []string{
			"online_access",
			"openid",
			"fhirUser",
			"profile",
			"launch",
			"user/Patient.read",
			"user/Patient.search",
			"user/Practitioner.Read",
		},
		// EndpointParams urlValues,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/authorize",
			TokenURL: "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token",
		},
	}

	return &FhirProvider{
		config: config,
		UserInfo: func(t *FhirTokenResponse) (*UserInfo, error) {
			key, err := fetchEpicJWKSKeyID()
			if err != nil {
				return nil, err
			}

			idToken, err := jwt.ParseNoVerify([]byte(t.IdToken))
			var epicIdTokenClaims *EpicIdTokenClaim
			json.Unmarshal(idToken.Claims(), &epicIdTokenClaims)

			if idToken.Header().KeyID == key {
				fmt.Println("=========== Key ID matches ===========")
				var user UserInfo
				user.ID = epicIdTokenClaims.Subject
				user.Email = epicIdTokenClaims.Subject // User's email is going to be user's ID on Epic
				fmt.Println(user)
				return &user, err
			} else {
				fmt.Println("=========== Key ID does not match ===========")
				return nil, err
			}
		},
	}
}
