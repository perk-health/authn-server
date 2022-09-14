package smart_on_fhir

import (
	"encoding/json"
	"errors"

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
			// 1. Get the JWKS from Epic
			keys, err := fetchEpicJWKS()
			if err != nil {
				return nil, err // No JWKS, can't verify the JWT, return an error
			}

			// 2. Verify the ID Token
			verifiedToken, err := verifyEpicIdToken(keys, t)
			if err != nil {
				return nil, err // verification failed, return an error
			}

			// 3. Get the user info from the ID Token & return it
			var user UserInfo
			user.ID = verifiedToken.Subject
			user.Email = verifiedToken.Subject // User's email is going to be user's ID on Epic
			return &user, err
		},
	}
}

func verifyEpicIdToken(keys *EpicJwksResponse, tokenResponse *FhirTokenResponse) (*EpicIdTokenClaim, error) {
	// 1. Parse the JWT and extract it's data WITHOUT verifying the signature
	idToken, err := jwt.ParseNoVerify([]byte(tokenResponse.IdToken))
	if err != nil {
		return nil, err
	}

	// 2. Convert the JWT to a map
	var tokenClaims *EpicIdTokenClaim
	json.Unmarshal(idToken.Claims(), &tokenClaims)

	// 3. Find the key that matches the key ID in the JWT
	hasJwks := false
	var rsaPublicKey *rsa.PublicKey
	for _, key := range keys.Keys {
		if key.KeyID == idToken.Header().KeyID {
			rsaPublicKey, err = buildRSAPublicKey(key.Modulus, key.Exponent)
			hasJwks = true
			break
		}
	}

	// 4. If we don't have a key, we can't verify the JWT. Return an error
	if !hasJwks {
		return nil, errors.New("No matching key found for ID Token")
	}

	// 5. Verify the JWT
	verifier, err := jwt.NewVerifierRS(jwt.RS256, rsaPublicKey)
	_, err = jwt.Parse([]byte(tokenResponse.IdToken), verifier)

	// 6. If verification failed, return an error
	if err != nil {
		return nil, err
	}

	return tokenClaims, nil
}
