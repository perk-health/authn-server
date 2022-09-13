package handlers

import (
	"fmt"
	"net/http"

	"github.com/keratin/authn-server/app"
	"github.com/keratin/authn-server/lib/smart_on_fhir"
	"github.com/pkg/errors"
)

func GetFhirReturn(app *app.App, providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("---- Starting: GetFhirReturn ----")

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
			fmt.Println("Error getting token:", err)
			fail(err)
			return
		}
		providerUser, err := provider.UserInfo(tokenResponse)
		if err != nil {
			fmt.Println("Error getting user info:", err)
			fail(err)
			return
		}

		fmt.Println("GetFhirReturn: providerUser:", providerUser.Email)

		// TODO: Figure out proper way to extract user information to link with OAuth account

		// attempt to reconcile oauth identity information into an authn account
		// sessionAccountID := sessions.GetAccountID(r)
		// account, err := services.IdentityReconciler(app.AccountStore, app.Config, providerName, providerUser, tok, sessionAccountID)
		// if err != nil {
		// 	// fail(err)
		// 	return
		// }

		// // identityToken is not returned in this flow. it must be imported by the frontend like a SSO session.
		// sessionToken, _, err := services.SessionCreator(
		// 	app.AccountStore, app.RefreshTokenStore, app.KeyStore, app.Actives, app.Config, app.Reporter,
		// 	account.ID, &app.Config.ApplicationDomains[0], sessions.GetRefreshToken(r),
		// )
		// if err != nil {
		// 	// fail(errors.Wrap(err, "NewSession"))
		// 	return
		// }

		// // Return the signed session in a cookie
		// sessions.Set(app.Config, w, sessionToken)

		// redirect back to frontend (success or failure)
		fmt.Println("===> state.Destination:", state.Destination)
		http.Redirect(w, r, state.Destination, http.StatusSeeOther)
	}
}
