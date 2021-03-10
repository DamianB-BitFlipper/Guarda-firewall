package webauthn_firewall

import (
	"fmt"
	"net/http"
	"reflect"

	log "unknwon.dev/clog/v2"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/db"

	"webauthn/protocol"
)

func logRequest(r *ExtendedRequest) {
	log.Info("%s:\t%s", r.Request.Method, r.Request.URL)
}

func (wfirewall *WebauthnFirewall) prepareJSONResponse(w http.ResponseWriter) {
	// Set the header info
	w.Header().Set("Access-Control-Allow-Origin", wfirewall.FrontendAddress)
	w.Header().Set("Content-Type", "application/json")
}

func (wfirewall *WebauthnFirewall) preamble(w http.ResponseWriter, r *ExtendedRequest) {
	// Print the HTTP request if verbosity is on
	if wfirewall.verbose {
		logRequest(r)
	}

	// Allow transmitting cookies, used by `sessionStore`
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func (wfirewall *WebauthnFirewall) proxyRequest(w http.ResponseWriter, r *ExtendedRequest) {
	// Print the HTTP request if verbosity is on
	if wfirewall.verbose {
		logRequest(r)
	}

	wfirewall.ServeHTTP(w, r.Request)
}

func (wfirewall *WebauthnFirewall) ProxyRequest(w http.ResponseWriter, r *ExtendedRequest) {
	// If an error has already occured, exit now
	if r.err != nil {
		log.Error("%v", r.err)
		http.Error(w, r.err.Error(), http.StatusInternalServerError)
		return
	}

	// Refill before proxying onward
	r.Refill()
	wfirewall.proxyRequest(w, r)
}

func checkWebauthnAssertion(
	r *ExtendedRequest,
	query db.WebauthnQuery,
	expectedExtensions protocol.AuthenticationExtensions,
	assertion string) error {

	// Get a `webauthnUser` from the input `query`
	wuser, err := db.WebauthnStore.GetWebauthnUser(query)
	if err != nil {
		return err
	}

	// Load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r.Request)
	if err != nil {
		return err
	}

	// Verify the transaction authentication text
	var verifyTxAuthSimple protocol.ExtensionsVerifier = func(_, clientDataExtensions protocol.AuthenticationExtensions) error {
		if !reflect.DeepEqual(expectedExtensions, clientDataExtensions) {
			return fmt.Errorf("Extensions verification failed: Expected %v, Received %v",
				expectedExtensions,
				clientDataExtensions)
		}

		// Successfully verified the extensions!
		return nil
	}

	// TODO: In an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = webauthnAPI.FinishLogin(wuser, sessionData, verifyTxAuthSimple, assertion)
	if err != nil {
		return err
	}

	// Success!
	return nil
}

func (wfirewall *WebauthnFirewall) webauthnSecure(getAuthnText func(*ExtendedRequest) string) func(http.ResponseWriter, *ExtendedRequest) {
	return func(w http.ResponseWriter, r *ExtendedRequest) {
		// If an error has already occured, exit now
		if r.err != nil {
			log.Error("%v", r.err)
			http.Error(w, r.err.Error(), http.StatusInternalServerError)
			return
		}

		// Call the firewall preamble
		wfirewall.preamble(w, r)

		// Retrieve the `userID` associated with the current request
		userID, err := r.GetUserID()
		if err != nil {
			log.Error("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// See if the user has webauthn enabled
		isEnabled := db.WebauthnStore.IsUserEnabled(db.QueryByUserID(userID))

		// Perform a webauthn check if webauthn is enabled for this user
		if isEnabled {
			// Parse the form-data to retrieve the `http.Request` information
			assertion, err := r.Get_WithErr("assertion")
			if err != nil {
				log.Error("%v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Get the `authnText` to verify against
			authnText := getAuthnText(r)

			// Check if there were any errors from `getAuthnText`
			if r.err != nil {
				log.Error("%v", r.err)
				http.Error(w, r.err.Error(), http.StatusInternalServerError)
				return
			}

			// Populate the `extensions` with the `authnText`
			extensions := make(protocol.AuthenticationExtensions)
			extensions["txAuthSimple"] = authnText

			// Check the webauthn assertion for this operation
			err = checkWebauthnAssertion(r, db.QueryByUserID(userID), extensions, assertion)
			if err != nil {
				log.Error("%v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Refill the `request` data before proxying onward
			r.Refill()
		}

		// Once the webauthn check passed, pass the request onward to
		// the server to check the username and password
		wfirewall.ServeHTTP(w, r.Request)
		return
	}
}
