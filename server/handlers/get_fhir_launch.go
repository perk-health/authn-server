package handlers

import (
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/app/tokens/oauth"
	"github.com/keratin/authn-server/lib"
)

func GetFhirLaunch(app *app.App, providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURI := app.Config.AuthNURL.String() + "/fhir/" + providerName + "/return"
		provider := app.SmartOnFhirProviders[providerName]
		issuer := r.FormValue("iss")
		launch := r.FormValue("launch")

		// Not currently used, but could be:
		// metadata := new(OpenIDConfiguration)
		// discoverAuthServer(issuer, metadata)

		// set nonce in a secured cookie
		bytes, err := lib.GenerateToken()
		if err != nil {
			WriteData(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		}
		nonce := base64.StdEncoding.EncodeToString(bytes)
		http.SetCookie(w, nonceCookie(app.Config, string(nonce)))

		// save nonce and return URL into state param
		// TODO: configure and store the URL of the application to redirect to
		// after the authorization process is complete. This is NOT the AuthN Server URL,
		// but the URL of the application
		stateToken, err := oauth.New(app.Config, string(nonce), redirectURI)
		if err != nil {
			WriteData(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		}
		state, _ := stateToken.Sign(app.Config.OAuthSigningKey)

		// Create the URL to redirect to
		finalRedirectUrl, _ := url.Parse(provider.Config(redirectURI).AuthCodeURL(state))

		// Add the launch and aud parameters to the URL
		// http://www.hl7.org/fhir/smart-app-launch/app-launch.html#request-4
		values := finalRedirectUrl.Query()
		values.Add("launch", launch)
		values.Add("aud", issuer)
		finalRedirectUrl.RawQuery = values.Encode()

		// Redirect user to the final URL
		http.Redirect(w, r, finalRedirectUrl.String(), http.StatusSeeOther)
	}
}
