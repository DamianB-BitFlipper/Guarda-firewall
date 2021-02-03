package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	log "unknwon.dev/clog/v2"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/db"
	"webauthn/protocol"
	"webauthn/webauthn"
	"webauthn_utils/session"
)

const (
	frontendPort     int = 4100
	backendPort      int = 8080
	reverseProxyPort int = 8081

	ENV_SESSION_KEY string = "SESSION_KEY"

	verbose bool = true
)

var (
	frontendAddress     string = fmt.Sprintf("https://localhost:%d", frontendPort)
	backendAddress      string = fmt.Sprintf("http://localhost:%d", backendPort)
	reverseProxyAddress string = fmt.Sprintf("localhost:%d", reverseProxyPort)

	webauthnAPI  *webauthn.WebAuthn
	sessionStore *session.Store
)

func logRequest(r *http.Request) {
	log.Info("%s:\t%s", r.Method, r.URL)
}

func userIDFromJWT(r *http.Request) (int64, error) {
	// The `tokenString` is the second part after the space in the `authorizationString`
	authorizationString := r.Header.Get("Authorization")
	tokenString := strings.Split(authorizationString, " ")[1]

	// Parse the JWT token
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return 0, err
	}

	// Extract the `userID` from the JWT token
	userID, ok := token.Claims.(jwt.MapClaims)["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("Unable to decode userID from JWT token")
	}

	return int64(userID), nil
}

type WebauthnFirewall struct {
	*httputil.ReverseProxy
}

func NewWebauthnFirewall() *WebauthnFirewall {
	origin, _ := url.Parse(backendAddress)

	director := func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", origin.Host)
		req.URL.Scheme = "http"
		req.URL.Host = origin.Host
	}

	proxyModifyResponse := func(r *http.Response) error {
		// Change the access control origin for all responses
		// coming back from the reverse proxy server
		r.Header.Set("Access-Control-Allow-Origin", frontendAddress)
		return nil
	}

	// Construct and return the webauthn firewall
	return &WebauthnFirewall{
		&httputil.ReverseProxy{
			Director:       director,
			ModifyResponse: proxyModifyResponse,
		},
	}
}

func (proxy *WebauthnFirewall) preamble(w http.ResponseWriter, r *http.Request) {
	if verbose {
		logRequest(r)
	}

	// Set the header info
	w.Header().Set("Access-Control-Allow-Origin", frontendAddress)
	w.Header().Set("Content-Type", "application/json")
}

func (proxy *WebauthnFirewall) proxyRequest(w http.ResponseWriter, r *http.Request) {
	// Print the HTTP request if verbosity is on
	if verbose {
		logRequest(r)
	}

	proxy.ServeHTTP(w, r)
}

func (proxy *WebauthnFirewall) optionsHandler(allowMethods ...string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if verbose {
			logRequest(r)
		}
		// Set the return OPTIONS
		w.Header().Set("Access-Control-Allow-Headers", "Origin,Content-Type,Accept,Authorization")
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowMethods, ","))
		w.Header().Set("Access-Control-Allow-Origin", frontendAddress)
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		w.WriteHeader(http.StatusNoContent)
	}
}

// TODO!: Check some sort of token before responding to this since any user can
// be queried with the GET to retrieve their webauthn status
func (proxy *WebauthnFirewall) webauthnIsEnabled(w http.ResponseWriter, r *http.Request) {
	// Call the proxy preamble
	proxy.preamble(w, r)

	// Get the `user` variable passed in the url
	vars := mux.Vars(r)
	username := vars["user"]

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

func (proxy *WebauthnFirewall) beginRegister(w http.ResponseWriter, r *http.Request) {
	// Call the proxy preamble
	proxy.preamble(w, r)

	// Allow transmitting cookies, used by `sessionStore`
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// Retrieve the `userID` from the JWT token contained in the `http.Request`
	userID, err := userIDFromJWT(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the JSON `http.Request` for the `Username`
	var reqBody struct {
		Username string `json:"username"`
	}

	err = json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new `webauthnUser` struct from the input details
	wuser := db.NewWebauthnUser(userID, reqBody.Username, nil)

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
	err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the `json_response`
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)
}

func (proxy *WebauthnFirewall) finishRegister(w http.ResponseWriter, r *http.Request) {
	// Call the proxy preamble
	proxy.preamble(w, r)

	// Allow transmitting cookies, used by `sessionStore`
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// Retrieve the `userID` from the JWT token contained in the `http.Request`
	userID, err := userIDFromJWT(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the JSON `http.Request`
	var reqBody struct {
		Username  string `json:"username"`
		Assertion string `json:"assertion"`
	}

	err = json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new `webauthnUser` struct from the input details
	wuser := db.NewWebauthnUser(userID, reqBody.Username, nil)

	// Load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webauthnAPI.FinishRegistration(wuser, sessionData, reqBody.Assertion)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Save the `credential` to the database
	db.WebauthnStore.Create(wuser, credential)

	// Success!
	w.WriteHeader(http.StatusOK)
}

// TODO: They way errors are handled on the front end are slightly different
// than this `http.Error` stuff
func (proxy *WebauthnFirewall) beginAttestation_base(
	query db.WebauthnQuery, clientExtensions protocol.AuthenticationExtensions,
	w http.ResponseWriter, r *http.Request) {

	// Allow transmitting cookies, used by `sessionStore`
	w.Header().Set("Access-Control-Allow-Credentials", "true")

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

	// The `clientExtensions` in BeginLogin is now superfluous
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
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the `json_response`
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)
}

func (proxy *WebauthnFirewall) beginAttestation(w http.ResponseWriter, r *http.Request) {
	// Call the proxy preamble
	proxy.preamble(w, r)

	// Retrieve the `userID` from the JWT token contained in the `http.Request`
	userID, err := userIDFromJWT(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the JSON `http.Request`
	var reqBody struct {
		AuthenticationText string `json:"auth_text"`
	}

	err = json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the transaction authentication extension
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = reqBody.AuthenticationText

	proxy.beginAttestation_base(db.QueryByUserID(userID), extensions, w, r)
	return
}

func (proxy *WebauthnFirewall) beginLogin(w http.ResponseWriter, r *http.Request) {
	// Call the proxy preamble
	proxy.preamble(w, r)

	// Parse the JSON `http.Request`
	var reqBody struct {
		Username string `json:"username"`
	}

	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	proxy.beginAttestation_base(db.QueryByUsername(reqBody.Username), nil, w, r)
	return
}

func (proxy *WebauthnFirewall) finishLogin(w http.ResponseWriter, r *http.Request) {
	// Print the HTTP request if verbosity is on
	if verbose {
		logRequest(r)
	}

	// Allow transmitting cookies, used by `sessionStore`
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// Get the `data` from the `http.Request` so that it can be restored again if necessary
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the JSON `http.Request` now read into `data`
	var reqBody struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
		Assertion string `json:"assertion"`
	}

	err = json.NewDecoder(bytes.NewReader(data)).Decode(&reqBody)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// See if the user has webauthn enabled
	isEnabled := db.WebauthnStore.IsUserEnabled(db.QueryByUsername(reqBody.User.Username))

	// Perform a webauthn check if webauthn is enabled for this user
	if isEnabled {
		// Get a `webauthnUser` for the requested username
		wuser, err := db.WebauthnStore.GetWebauthnUser(db.QueryByUsername(reqBody.User.Username))
		if err != nil {
			log.Error("%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Load the session data
		sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
		if err != nil {
			log.Error("%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// There are no extensions to verify during login authentication
		var noVerify protocol.ExtensionsVerifier = func(_, _ protocol.AuthenticationExtensions) error {
			return nil
		}

		// TODO: In an actual implementation, we should perform additional checks on
		// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
		// and then increment the credentials counter
		_, err = webauthnAPI.FinishLogin(wuser, sessionData, noVerify, reqBody.Assertion)
		if err != nil {
			log.Error("%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Before proxying the response onward, restore the `r.Body` field
	r.Body = ioutil.NopCloser(bytes.NewReader(data))

	// Once the webauthn check passed, pass the request onward to
	// the server to check the username and password
	proxy.ServeHTTP(w, r)
	return
}

func (proxy *WebauthnFirewall) disableWebauthn(w http.ResponseWriter, r *http.Request) {
	// Call the proxy preamble
	proxy.preamble(w, r)

	// Allow transmitting cookies, used by `sessionStore`
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// Retrieve the `userID` from the JWT token contained in the `http.Request`
	userID, err := userIDFromJWT(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the JSON `http.Request` now read into `data`
	var reqBody struct {
		Assertion string `json:"assertion"`
	}

	err = json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get a `webauthnUser` for the `userID`
	wuser, err := db.WebauthnStore.GetWebauthnUser(db.QueryByUserID(userID))
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify the transaction authentication text
	var verifyTxAuthSimple protocol.ExtensionsVerifier = func(_, clientDataExtensions protocol.AuthenticationExtensions) error {
		expectedExtensions := protocol.AuthenticationExtensions{
			"txAuthSimple": fmt.Sprintf("Confirm disable webauthn for %v", wuser.WebAuthnName()),
		}

		if !reflect.DeepEqual(expectedExtensions, clientDataExtensions) {
			return fmt.Errorf("Extensions verification failed: Expected %v, Received %v",
				expectedExtensions,
				clientDataExtensions)
		}

		// Success!
		return nil
	}

	// TODO: In an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = webauthnAPI.FinishLogin(wuser, sessionData, verifyTxAuthSimple, reqBody.Assertion)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Save the `credential` to the database
	db.WebauthnStore.Delete(wuser.WebAuthnName())

	// Success!
	w.WriteHeader(http.StatusOK)
}

// TODO: There is a lot of opportunity to condense this code into common functions
// Can the front end just set the `username` to something garbled -> isEnabled = false, vioala!
func (proxy *WebauthnFirewall) deleteComment(w http.ResponseWriter, r *http.Request) {
	// Print the HTTP request if verbosity is on
	if verbose {
		logRequest(r)
	}

	// Allow transmitting cookies, used by `sessionStore`
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// Retrieve the `userID` from the JWT token contained in the `http.Request`
	userID, err := userIDFromJWT(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the `data` from the `http.Request` so that it can be restored again if necessary
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the JSON `http.Request` now read into `data`
	var reqBody struct {
		Assertion string `json:"assertion"`
	}

	err = json.NewDecoder(bytes.NewReader(data)).Decode(&reqBody)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// See if the user has webauthn enabled
	isEnabled := db.WebauthnStore.IsUserEnabled(db.QueryByUserID(userID))

	// Perform a webauthn check if webauthn is enabled for this user
	if isEnabled {
		// Get a `webauthnUser` for the requested username
		wuser, err := db.WebauthnStore.GetWebauthnUser(db.QueryByUserID(userID))
		if err != nil {
			log.Error("%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Load the session data
		sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
		if err != nil {
			log.Error("%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Verify the transaction authentication text
		var verifyTxAuthSimple protocol.ExtensionsVerifier = func(_, clientDataExtensions protocol.AuthenticationExtensions) error {
			expectedExtensions := protocol.AuthenticationExtensions{
				"txAuthSimple": "Confirm comment delete",
			}

			if !reflect.DeepEqual(expectedExtensions, clientDataExtensions) {
				return fmt.Errorf("Extensions verification failed: Expected %v, Received %v",
					expectedExtensions,
					clientDataExtensions)
			}

			// Success!
			return nil
		}

		// TODO: In an actual implementation, we should perform additional checks on
		// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
		// and then increment the credentials counter
		_, err = webauthnAPI.FinishLogin(wuser, sessionData, verifyTxAuthSimple, reqBody.Assertion)
		if err != nil {
			log.Error("%v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Before proxying the response onward, restore the `r.Body` field
	r.Body = ioutil.NopCloser(bytes.NewReader(data))

	// Once the webauthn check passed, pass the request onward to
	// the server to check the username and password
	proxy.ServeHTTP(w, r)
	return
}

func main() {
	// Initialize a new webauthn firewall
	wfirewall := NewWebauthnFirewall()

	// Initialize the database for the firewall
	log.Info("Starting up database")
	if err := db.Init(); err != nil {
		panic("Unable to initialize database: " + err.Error())
	}

	// Register the HTTP routes
	r := mux.NewRouter()

	// Proxy routes
	r.HandleFunc("/api/user", wfirewall.proxyRequest).Methods("OPTIONS", "GET", "POST", "PUT")
	r.HandleFunc("/api/tags", wfirewall.proxyRequest).Methods("OPTIONS", "GET")
	r.HandleFunc("/api/profiles/{user}", wfirewall.proxyRequest).Methods("OPTIONS", "GET")
	r.HandleFunc("/api/articles/feed", wfirewall.proxyRequest).Methods("OPTIONS", "GET")
	r.HandleFunc("/api/articles", wfirewall.proxyRequest).Methods("OPTIONS", "GET", "POST")
	r.HandleFunc("/api/articles/{slug}", wfirewall.proxyRequest).Methods("OPTIONS", "GET", "DELETE")
	r.HandleFunc("/api/articles/{slug}/comments", wfirewall.proxyRequest).Methods("OPTIONS", "GET", "POST")

	// Webauthn and other intercepted routes
	r.HandleFunc("/api/webauthn/is_enabled/{user}", wfirewall.optionsHandler("GET")).Methods("OPTIONS")
	r.HandleFunc("/api/webauthn/is_enabled/{user}", wfirewall.webauthnIsEnabled).Methods("GET")

	r.HandleFunc("/api/webauthn/begin_register", wfirewall.optionsHandler("POST")).Methods("OPTIONS")
	r.HandleFunc("/api/webauthn/begin_register", wfirewall.beginRegister).Methods("POST")

	r.HandleFunc("/api/webauthn/finish_register", wfirewall.optionsHandler("POST")).Methods("OPTIONS")
	r.HandleFunc("/api/webauthn/finish_register", wfirewall.finishRegister).Methods("POST")

	r.HandleFunc("/api/webauthn/begin_login", wfirewall.optionsHandler("POST")).Methods("OPTIONS")
	r.HandleFunc("/api/webauthn/begin_login", wfirewall.beginLogin).Methods("POST")

	r.HandleFunc("/api/users/login", wfirewall.optionsHandler("POST")).Methods("OPTIONS")
	r.HandleFunc("/api/users/login", wfirewall.finishLogin).Methods("POST")

	r.HandleFunc("/api/webauthn/begin_attestation", wfirewall.optionsHandler("POST")).Methods("OPTIONS")
	r.HandleFunc("/api/webauthn/begin_attestation", wfirewall.beginAttestation).Methods("POST")

	r.HandleFunc("/api/webauthn/disable", wfirewall.optionsHandler("POST")).Methods("OPTIONS")
	r.HandleFunc("/api/webauthn/disable", wfirewall.disableWebauthn).Methods("POST")

	r.HandleFunc("/api/articles/{slug}/comments/{comment_id}", wfirewall.optionsHandler("DELETE")).Methods("OPTIONS")
	r.HandleFunc("/api/articles/{slug}/comments/{comment_id}", wfirewall.deleteComment).Methods("DELETE")

	// Start up the server
	log.Info("Starting up server on port: %d", reverseProxyPort)
	log.Info("Forwarding HTTP: %d -> %d", reverseProxyPort, backendPort)

	log.Fatal("%v", http.ListenAndServe(reverseProxyAddress, r))

	// Graceful stopping all loggers before exiting the program.
	log.Stop()
}

func init() {
	// Initialize the logger code
	err := log.NewConsole()
	if err != nil {
		panic("Unable to create new logger: " + err.Error())
	}

	// Initialize the Webauthn API code
	webauthnAPI, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",  // Display Name for your site
		RPID:          "localhost",     // Generally the domain name for your site
		RPOrigin:      frontendAddress, // Have the front-end be the origin URL for WebAuthn requests
	})
	if err != nil {
		panic("Unable to initialize Webauthn API: " + err.Error())
	}

	// Get the session key from the environment variable
	sessionKey, err := hex.DecodeString(os.Getenv(ENV_SESSION_KEY))
	if err != nil {
		panic("Failed to decode session key env variable: " + err.Error())
	}

	if len(sessionKey) < session.DefaultEncryptionKeyLength {
		panic(fmt.Sprintf("Session key not long enough: %d < %d",
			len(sessionKey), session.DefaultEncryptionKeyLength))
	}

	// Initialize the Webauthn `sessionStore`
	sessionStore, err = session.NewStore(sessionKey)
	if err != nil {
		panic("Failed to create webauthn session store: " + err.Error())
	}
}

func genSessionKey() {
	key, err := session.GenerateSecureKey(session.DefaultEncryptionKeyLength)
	if err != nil {
		panic("Unable to generate secure session key: " + err.Error())
	}

	fmt.Printf("export %s=%s\n", ENV_SESSION_KEY, hex.EncodeToString(key))
}
