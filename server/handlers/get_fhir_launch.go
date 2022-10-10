package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/app/tokens/oauth"
	"github.com/keratin/authn-server/lib"
	"github.com/keratin/authn-server/lib/route"
	"github.com/keratin/authn-server/lib/smart_on_fhir"
)

func GetFhirLaunch(app *app.App, providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := app.SmartOnFhirProviders[providerName]
		issuer := r.FormValue("iss")
		launch := r.FormValue("launch")
		redirectURI := r.FormValue("redirect_uri")                                           // redirect URI to the UI
		authnReturnUri := app.Config.AuthNURL.String() + "/fhir/" + providerName + "/return" // Authn to return to after login

		if route.FindDomain(redirectURI, app.Config.ApplicationDomains) == nil {
			app.Reporter.ReportRequestError(errors.New("unknown redirect domain"), r)
			failsafe := app.Config.ApplicationDomains[0].URL()
			http.Redirect(w, r, failsafe.String(), http.StatusSeeOther)
			return
		}

		// fail handler
		fail := func(err error) {
			app.Reporter.ReportRequestError(err, r)
			redirectFailure(w, r, redirectURI)
		}

		// set nonce in a secured cookie
		bytes, err := lib.GenerateToken()
		if err != nil {
			fail(err)
			return
		}
		nonce := base64.StdEncoding.EncodeToString(bytes)
		http.SetCookie(w, nonceCookie(app.Config, string(nonce)))

		// save nonce and return URL into state param
		stateToken, err := oauth.New(app.Config, string(nonce), redirectURI)
		if err != nil {
			fail(err)
			return
		}
		state, _ := stateToken.Sign(app.Config.OAuthSigningKey)

		// Create the URL to redirect to
		// returnUrl, _ := buildAuthnReturnUrl(authnReturnUri, provider, state, launch, issuer)
		returnUrl, _ := buildAuthnReturnUrl(authnReturnUri, provider, state, launch, issuer)

		// Redirect user to the final URL
		http.Redirect(w, r, returnUrl.String(), http.StatusSeeOther)
	}
}

func buildAuthnReturnUrl(baseUri string, provider smart_on_fhir.FhirProvider, state string, launch string, issuer string) (*url.URL, error) {
	returnUrl, err := url.Parse(provider.Config(baseUri).AuthCodeURL(state))

	// Add the launch and aud parameters to the URL
	// http://www.hl7.org/fhir/smart-app-launch/app-launch.html#request-4
	values := returnUrl.Query()
	values.Add("launch", launch)
	values.Add("aud", issuer)
	returnUrl.RawQuery = values.Encode()

	return returnUrl, err
}
