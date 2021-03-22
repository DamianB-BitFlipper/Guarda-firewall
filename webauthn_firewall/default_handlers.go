package webauthn_firewall

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "unknwon.dev/clog/v2"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/db"

	"webauthn/protocol"
)

// TODO!: Check some sort of token before responding to this since any user can
// be queried with the GET to retrieve their webauthn status
func (wfirewall *WebauthnFirewall) webauthnIsEnabled(w http.ResponseWriter, r *ExtendedRequest) {
	// Print the HTTP request if verbosity is on
	if wfirewall.verbose {
		logRequest(r)
	}

	// Prepare the response for a JSON object return
	wfirewall.prepareJSONResponse(w)

	// Get the `user` variable passed in the url
	username := r.GetURLInput("user")

	isEnabled := db.WebauthnStore.IsUserEnabled(db.QueryByUsername(username))

	// Marshal a response `webauthn_is_enabled` field
	json_response, err := json.Marshal(map[string]bool{"webauthn_is_enabled": isEnabled})
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the `json_response`
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)
}

func (wfirewall *WebauthnFirewall) beginRegister(w http.ResponseWriter, r *ExtendedRequest) {
	// Call the firewall preamble
	wfirewall.preamble(w, r)

	// Prepare the response for a JSON object return
	wfirewall.prepareJSONResponse(w)

	// Parse the form-data to retrieve the `http.Request` information
	username, err := r.Get_WithErr("username")
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve the `userID` associated with the current request
	userID, err := r.GetUserID()
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new `webauthnUser` struct from the input details
	wuser := db.NewWebauthnUser(userID, username, nil)

	// TODO
	// registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
	// 	credCreationOpts.CredentialExcludeList = wuser.CredentialExcludeList()
	// }

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webauthnAPI.BeginRegistration(
		wuser,
		// TODO registerOptions,
	)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert the `options` into JSON format
	json_response, err := json.Marshal(options.Response)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Save the `sessionData` as marshaled JSON
	err = sessionStore.SaveWebauthnSession("registration", sessionData, r.Request, w)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the `json_response`
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)
}

func (wfirewall *WebauthnFirewall) finishRegister(w http.ResponseWriter, r *ExtendedRequest) {
	// Call the firewall preamble
	wfirewall.preamble(w, r)

	// Prepare the response for a JSON object return
	wfirewall.prepareJSONResponse(w)

	// Parse the form-data to retrieve the `http.Request` information
	username, err := r.Get_WithErr("username")
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	credentials, err := r.Get_WithErr("credentials")
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Retrieve the `userID` associated with the current request
	userID, err := r.GetUserID()
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new `webauthnUser` struct from the input details
	wuser := db.NewWebauthnUser(userID, username, nil)

	// Load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r.Request)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	wcredential, err := webauthnAPI.FinishRegistration(wuser, sessionData, credentials)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Marshal a response `redirectTo` field to reload the page
	json_response, err := json.Marshal(map[string]string{"redirectTo": ""})
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Save the `wcredential` to the database
	db.WebauthnStore.Create(wuser, wcredential)

	// Success!
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)
}

// TODO: They way errors are handled on the front end are slightly different
// than this `http.Error` stuff
func (wfirewall *WebauthnFirewall) beginAttestation_base(
	query db.WebauthnQuery, clientExtensions protocol.AuthenticationExtensions,
	w http.ResponseWriter, r *ExtendedRequest) {

	// See if the user has webauthn enabled
	isEnabled := db.WebauthnStore.IsUserEnabled(query)

	// Do nothing if the user does not have webauthn enabled
	if !isEnabled {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get a `webauthnUser` from the input `query`
	wuser, err := db.WebauthnStore.GetWebauthnUser(query)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: The `clientExtensions` in BeginLogin is now superfluous
	//
	// Generate the webauthn `options` and `sessionData`
	options, sessionData, err := webauthnAPI.BeginLogin(wuser, nil)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Add the `clientExtensions` onto the webauthn `options`
	options.Response.Extensions = clientExtensions

	// Convert the `options` into JSON format
	json_response, err := json.Marshal(options.Response)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r.Request, w)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the `json_response`
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)
}

func (wfirewall *WebauthnFirewall) beginAttestation(w http.ResponseWriter, r *ExtendedRequest) {
	// Call the firewall preamble
	wfirewall.preamble(w, r)

	// Prepare the response for a JSON object return
	wfirewall.prepareJSONResponse(w)

	// Retrieve the `userID` associated with the current request
	userID, err := r.GetUserID()
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the form-data to retrieve the `http.Request` information
	authenticationText, err := r.Get_WithErr("auth_text")
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the transaction authentication extension
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = authenticationText

	wfirewall.beginAttestation_base(db.QueryByUserID(userID), extensions, w, r)
	return
}

func (wfirewall *WebauthnFirewall) beginLogin(w http.ResponseWriter, r *ExtendedRequest) {
	// Call the firewall preamble
	wfirewall.preamble(w, r)

	// Prepare the response for a JSON object return
	wfirewall.prepareJSONResponse(w)

	// Parse the form-data to retrieve the `http.Request` information
	username, err := r.Get_WithErr("username")
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	wfirewall.beginAttestation_base(db.QueryByUsername(username), nil, w, r)
	return
}

func (wfirewall *WebauthnFirewall) finishLogin(w http.ResponseWriter, r *ExtendedRequest) {
	// Call the firewall preamble
	wfirewall.preamble(w, r)

	// Get the username from the incoming login `http.Request`
	username, err := wfirewall.loginGetUsername(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	assertion, err := r.Get_WithErr("assertion")
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// See if the user has webauthn enabled
	isEnabled := db.WebauthnStore.IsUserEnabled(db.QueryByUsername(username))

	// Perform a webauthn check if webauthn is enabled for this user
	if isEnabled {
		// Check the webauthn assertion for this operation. There are no extensions to verify
		err = checkWebauthnAssertion(r, db.QueryByUsername(username), nil, assertion)
		if err != nil {
			log.Error("%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Refill the `request` data before proxying onward
	r.Refill()

	// Once the webauthn check passed, pass the request onward to
	// the server to check the username and password
	wfirewall.ServeHTTP(w, r)
	return
}

func (wfirewall *WebauthnFirewall) disableWebauthn(w http.ResponseWriter, r *ExtendedRequest) {
	// Call the firewall preamble
	wfirewall.preamble(w, r)

	// Prepare the response for a JSON object return
	wfirewall.prepareJSONResponse(w)

	// Retrieve the `userID` associated with the current request
	userID, err := r.GetUserID()
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the form-data to retrieve the `http.Request` information
	assertion, err := r.Get_WithErr("assertion")
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Construct a database user query by ID
	query := db.QueryByUserID(userID)

	// Get a `webauthnUser` for the `query`
	wuser, err := db.WebauthnStore.GetWebauthnUser(query)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = fmt.Sprintf("Confirm disable webauthn for %v", wuser.WebAuthnName())

	// Check the webauthn assertion for this operation.
	err = checkWebauthnAssertion(r, query, extensions, assertion)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Marshal a response `redirectTo` field to reload the page
	json_response, err := json.Marshal(map[string]string{"redirectTo": ""})
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Save the `credential` to the database
	db.WebauthnStore.Delete(wuser.WebAuthnName())

	// Success!
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)
}
