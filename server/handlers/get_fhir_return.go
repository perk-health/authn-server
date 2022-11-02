package handlers

import (
	"fmt"
	"net/http"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/app/services"
	"github.com/keratin/authn-server/lib/oauth"
	"github.com/keratin/authn-server/lib/smart_on_fhir"
	"github.com/keratin/authn-server/server/sessions"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

func GetFhirReturn(app *app.App, providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		provider := app.SmartOnFhirProviders[providerName]
		// exchange code for tokens and user info
		// redirectURI := app.Config.AuthNURL.String() + "/fhir/" + providerName + "/return"
		tokenUrl := provider.TokenUrl()
		clientId := provider.ClientID()
		clientSecret := provider.ClientSecret()
		state, err := getState(app.Config, r)
		if err != nil {
			app.Reporter.ReportRequestError(errors.Wrap(err, "getState"), r)
			failsafe := app.Config.ApplicationDomains[0].URL()
			http.Redirect(w, r, failsafe.String(), http.StatusSeeOther)
			return
		}
		http.SetCookie(w, nonceCookie(app.Config, ""))

		fail := func(err error) {
			app.Reporter.ReportRequestError(err, r)
			redirectFailure(w, r, state.Destination)
		}

		// ===> exchange code for tokens and user info
		tokenResponse, err := smart_on_fhir.RequestAccessToken(tokenUrl, clientId, clientSecret, r.FormValue("code"))
		if err != nil {
			fmt.Println("Error requesting access token: ")
			fail(err)
			return
		}

		fmt.Println("Finished Getting Token Response...")
		fmt.Println("tokenResponse.IdToken: ", tokenResponse.IdToken)
		fmt.Println("tokenResponse.AccessToken: ", tokenResponse.AccessToken)
		fmt.Println("tokenResponse.Scope: ", tokenResponse.Scope)
		fmt.Println("tokenResponse.Encounter: ", tokenResponse.Encounter)
		fmt.Println("tokenResponse.PatientFhirId: ", tokenResponse.PatientFhirId)
		fmt.Println("...")

		providerUser, err := provider.UserInfo(tokenResponse)
		if err != nil {
			fmt.Println("Error getting Provider User: ")
			fail(err)
			return
		}

		// ===> attempt to reconcile oauth identity information into an authn account and return a session token
		sessionToken, err := getSessionFromOauth(app, providerUser, tokenResponse, r, providerName)
		if err != nil {
			fmt.Println("Error getting session token: ")
			fail(err)
			return
		}
		// Return the signed session in a cookie
		sessions.Set(app.Config, w, sessionToken)

		// Set FHIR Information in a cookie
		cookie := &http.Cookie{
			Name:     "fhir_session",
			Value:    tokenResponse.AccessToken + "::" + tokenResponse.IdToken + "::" + tokenResponse.PatientFhirId,
			Path:     "/fhir/",
			Secure:   app.Config.ForceSSL,
			HttpOnly: false,
			SameSite: app.Config.SameSiteComputed(),
			// TODO: Set max age to a very low number.
			MaxAge: 100,
		}
		http.SetCookie(w, cookie)

		// redirect to the destination
		http.Redirect(w, r, state.Destination, http.StatusSeeOther)
	}
}

func getSessionFromOauth(app *app.App, providerUser *smart_on_fhir.UserInfo, tokenResponse *smart_on_fhir.FhirTokenResponse, r *http.Request, providerName string) (string, error) {
	// attempt to reconcile oauth identity information into an authn account
	sessionAccountID := sessions.GetAccountID(r)

	// Cast smartOnfhir structs to oauth structs b/c I don't know how to type cast them
	oauthProviderUser := &oauth.UserInfo{
		ID:    providerUser.ID,
		Email: providerUser.Email,
	}

	tok := &oauth2.Token{
		AccessToken: tokenResponse.AccessToken,
	}

	// Use oauth service to reconcile with existing identities
	account, err := services.IdentityReconciler(app.AccountStore, app.Config, providerName, oauthProviderUser, tok, sessionAccountID)
	if err != nil {
		return "", err
	}

	// identityToken is not returned in this flow. it must be imported by the frontend like a SSO session.
	sessionToken, _, err := services.SessionCreator(
		app.AccountStore, app.RefreshTokenStore, app.KeyStore, app.Actives, app.Config, app.Reporter,
		account.ID, &app.Config.ApplicationDomains[0], sessions.GetRefreshToken(r),
	)
	if err != nil {
		return "", err
	}

	return sessionToken, nil
}
