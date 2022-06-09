package smart_on_fhir

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"

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
			"user/Patient.rs",
			"user/Practitioner.rs",
			"user/Practitioner.Read",
			"patient/Practitioner.Read",
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
			// Steps:
			// 1. Extract the sub from the access token
			// 2. Combine the subject with the Practitioner endpoint to get user data
			// 3. Unmarshal the response into a Practitioner object

			var me struct {
				id string
				// telecom						contactPoint
			}

			oauth2Token := &oauth2.Token{
				AccessToken: t.AccessToken,
			}

			client := config.Client(context.TODO(), oauth2Token)
			resp, err := client.Get("https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/Practitioner/")
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			fmt.Println(string(body))

			var user UserInfo
			err = json.Unmarshal(body, &me)
			user.ID = me.id
			// user.Email = me.telecom[0].value
			fmt.Println(user)
			return &user, err
		},
	}
}
