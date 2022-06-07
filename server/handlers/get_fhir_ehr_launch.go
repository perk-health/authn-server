package handlers

import (
	"net/http"

	"github.com/keratin/authn-server/app"
)

func GetFhirEhrLaunch(app *app.App, providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		WriteData(w, http.StatusOK, map[string]interface{}{
			"working": "yes",
		})
	}
}
