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
