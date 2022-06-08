package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"golang.org/x/oauth2"
)

func NewEpicSmartOnFhirProvider(credentials *Credentials) *Provider {
	// urlValues := url.Values{}
	// urlValues.Set("launch", someLaunchCode)

	config := &oauth2.Config{
		ClientID:     credentials.ID,
		ClientSecret: credentials.Secret,
		Scopes:       []string{"online_access", "openid", "fhirUser", "profile", "launch", "user/Patient.rs"},
		// EndpointParams urlValues,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/authorize",
			TokenURL: "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token",
		},
	}

	return &Provider{
		config: config,
		UserInfo: func(t *oauth2.Token) (*UserInfo, error) {
			var me struct {
				id string
				// telecom						contactPoint
			}

			client := config.Client(context.TODO(), t)
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
