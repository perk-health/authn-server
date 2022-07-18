package smart_on_fhir

import (
	"encoding/json"
	"fmt"

	"crypto/rsa"

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
			keys, err := fetchEpicJWKS()
			if err != nil {
				return nil, err
			}

			idToken, err := jwt.ParseNoVerify([]byte(t.IdToken))
			var epicIdTokenClaims *EpicIdTokenClaim
			json.Unmarshal(idToken.Claims(), &epicIdTokenClaims)

			hasJwks := false
			var rsaPublicKey *rsa.PublicKey

			fmt.Println("==> Token kid:", idToken.Header().KeyID)
			for index, key := range keys.Keys {
				fmt.Println("===> Key", index + 1, "kid:", key.KeyID)

				if key.KeyID == idToken.Header().KeyID {
					rsaPublicKey, err = buildRSAPublicKey(key.Modulus, key.Exponent)
					hasJwks = true
					break
				}
			}

			// create a Verifier (HMAC in this example)
			verifier, err := jwt.NewVerifierRS(jwt.RS256, rsaPublicKey)

			_, err = jwt.Parse([]byte(t.IdToken), verifier)
			if err == nil {
				fmt.Println("=========== ID Token verified ===========")
			} else {
				return nil, err
			}

			if hasJwks {
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
