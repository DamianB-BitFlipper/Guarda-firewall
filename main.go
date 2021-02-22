package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	log "unknwon.dev/clog/v2"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/db"
	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/tool"

	"webauthn/protocol"
	"webauthn/webauthn"
	"webauthn_utils/session"
)

const (
	frontendPort     int = 8081
	backendPort      int = 3000
	reverseProxyPort int = 8081

	ENV_SESSION_KEY string = "SESSION_KEY"

	verbose bool = true
)

var (
	frontendAddress     string = fmt.Sprintf("https://localhost:%d", frontendPort)
	backendAddress      string = fmt.Sprintf("https://localhost:%d", backendPort)
	reverseProxyAddress string = fmt.Sprintf("localhost:%d", reverseProxyPort)

	webauthnAPI  *webauthn.WebAuthn
	sessionStore *session.Store
)

func logRequest(r *http.Request) {
	log.Info("%s:\t%s", r.Method, r.URL)
}

func printRequestContents(r *http.Request) error {
	// Save a copy of this request for debugging.
	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	log.Info(string(requestDump))

	// Success!
	return nil
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

	// Success!
	return int64(userID), nil
}

func userIDFromSession(r *http.Request) (int64, error) {
	// Get the UserID associated with the sessionID in the cookies. This is to assure that the
	// server and the firewall are referencing the same user during the webauthn check
	url := fmt.Sprintf("%s/server_context/session2user", backendAddress)
	userIDReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	// Pass on the cookies from `r` to `userIDReq`, which will include the cookie with the `sessionID`
	for _, cookie := range r.Cookies() {
		userIDReq.AddCookie(cookie)
	}

	var sessionInfo struct {
		Ok     bool  `json:"ok"`
		UserID int64 `json:"uid"`
	}
	err = tool.PerformRequestJSON(userIDReq, &sessionInfo)
	if err != nil {
		return 0, err
	}

	if !sessionInfo.Ok {
		return 0, fmt.Errorf("Unable to retrieve the userID for this cookie session")
	}

	// Success!
	return sessionInfo.UserID, nil
}

func itemFromItemID(itemType string, id int64, itemStruct interface{}) error {
	// Construct the URL to retrieve the item from the input item `id`
	url := fmt.Sprintf("%s/server_context/%s/%d", backendAddress, itemType, id)
	return tool.GetRequestJSON(url, itemStruct)
}

func itemFromItemStringID(itemType string, id string, itemStruct interface{}) error {
	// Construct the URL to retrieve the item from the input item `id`
	url := fmt.Sprintf("%s/server_context/%s/%s", backendAddress, itemType, id)
	return tool.GetRequestJSON(url, itemStruct)
}

func itemFromUserItemID(itemType string, userID, id int64, itemStruct interface{}) error {
	// Construct the URL to retrieve the item from the input item `id`
	url := fmt.Sprintf("%s/server_context/%s/%d/%d", backendAddress, itemType, userID, id)
	return tool.GetRequestJSON(url, itemStruct)
}

type SSHKey struct {
	Name    string
	Content string
}

func sshKeyFromSSHKeyID(sshKeyID int64) (*SSHKey, error) {
	publicKey := new(SSHKey)
	err := itemFromItemID("ssh_key", sshKeyID, publicKey)
	if err != nil {
		return nil, err
	}

	// Success!
	return publicKey, nil
}

type Email struct {
	Email string
}

func emailFromEmailID(emailID int64) (*Email, error) {
	email := new(Email)
	err := itemFromItemID("email", emailID, email)
	if err != nil {
		return nil, err
	}

	// Success!
	return email, nil
}

type Repo struct {
	Name string
}

func repoFromRepoID(repoID int64) (*Repo, error) {
	repo := new(Repo)
	err := itemFromItemID("repository", repoID, repo)
	if err != nil {
		return nil, err
	}

	// Success!
	return repo, nil
}

type AppToken struct {
	Name string
}

func appTokenFromAppTokenID(userID, id int64) (*AppToken, error) {
	appToken := new(AppToken)
	err := itemFromUserItemID("app_token", userID, id, appToken)
	if err != nil {
		return nil, err
	}

	// Success!
	return appToken, nil
}

type Attachment struct {
	Name string
}

func attachmentFromAttachmentID(uuid string) (*Attachment, error) {
	attachment := new(Attachment)
	err := itemFromItemStringID("attachment", uuid, attachment)
	if err != nil {
		return nil, err
	}

	// Success!
	return attachment, nil
}

func checkWebauthnAssertion(
	r *http.Request,
	query db.WebauthnQuery,
	expectedExtensions protocol.AuthenticationExtensions,
	assertion string) error {

	// Get a `webauthnUser` from the input `query`
	wuser, err := db.WebauthnStore.GetWebauthnUser(query)
	if err != nil {
		return err
	}

	// Load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
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

type RequestRefiller struct {
	request *http.Request
	data    []byte
}

func NewRequestRefiller(r *http.Request) (*RequestRefiller, error) {
	refill := new(RequestRefiller)

	// Get the `data` from the `http.Request` so that it can be restored again if necessary
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	// Set the `request` and `data` fields
	refill.request = r
	refill.data = data

	// Refill the `http.Request` since it was read during setup
	refill.Refill()

	// Success!
	return refill, nil
}

func (rf *RequestRefiller) Refill() {
	// Reload the `r.Body` from the `data` before reading the form fields
	rf.request.Body = ioutil.NopCloser(bytes.NewReader(rf.data))
}

type WebauthnFirewall struct {
	*httputil.ReverseProxy
}

func NewWebauthnFirewall() *WebauthnFirewall {
	origin, _ := url.Parse(backendAddress)
	proxy := httputil.NewSingleHostReverseProxy(origin)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Construct and return the webauthn firewall
	return &WebauthnFirewall{
		proxy,
	}
}

func (proxy *WebauthnFirewall) preamble(w http.ResponseWriter, r *http.Request) {
	// Print the HTTP request if verbosity is on
	if verbose {
		logRequest(r)
	}

	// Allow transmitting cookies, used by `sessionStore`
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

func (proxy *WebauthnFirewall) prepareJSONResponse(w http.ResponseWriter) {
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
		// Call the proxy preamble
		proxy.preamble(w, r)

		// Set the return OPTIONS
		w.Header().Set("Access-Control-Allow-Headers", "Origin,Content-Type,Accept,Authorization")
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowMethods, ","))
		w.Header().Set("Access-Control-Allow-Origin", frontendAddress)

		w.WriteHeader(http.StatusNoContent)
	}
}

func (proxy *WebauthnFirewall) webauthnSecure(
	getTxExtensions func(*http.Request) (protocol.AuthenticationExtensions, error),
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Call the proxy preamble
		proxy.preamble(w, r)

		// Retrieve the `userID` associated with the current session
		userID, err := userIDFromSession(r)
		if err != nil {
			log.Error("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// See if the user has webauthn enabled
		isEnabled := db.WebauthnStore.IsUserEnabled(db.QueryByUserID(userID))

		// Perform a webauthn check if webauthn is enabled for this user
		if isEnabled {
			// Instantiate a `RequestRefiller` since `r` will be read multiple times
			reqRefill, err := NewRequestRefiller(r)
			if err != nil {
				log.Error("%v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Parse the form-data to retrieve the `http.Request` information
			assertion := r.FormValue("assertion")
			if assertion == "" {
				errText := "Invalid form-data parameters"
				log.Error("%v", errText)
				http.Error(w, errText, http.StatusInternalServerError)
				return
			}

			// Get the `extensions` to verify against
			extensions, err := getTxExtensions(r)
			if err != nil {
				log.Error("%v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Check the webauthn assertion for this operation
			err = checkWebauthnAssertion(r, db.QueryByUserID(userID), extensions, assertion)
			if err != nil {
				log.Error("%v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Refill the `request` data before proxying onward
			reqRefill.Refill()
		}

		// Once the webauthn check passed, pass the request onward to
		// the server to check the username and password
		proxy.ServeHTTP(w, r)
		return
	}
}

// TODO!: Check some sort of token before responding to this since any user can
// be queried with the GET to retrieve their webauthn status
func (proxy *WebauthnFirewall) webauthnIsEnabled(w http.ResponseWriter, r *http.Request) {
	// Print the HTTP request if verbosity is on
	if verbose {
		logRequest(r)
	}

	// Prepare the response for a JSON object return
	proxy.prepareJSONResponse(w)

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

	// Prepare the response for a JSON object return
	proxy.prepareJSONResponse(w)

	// Parse the form-data to retrieve the `http.Request` information
	username := r.FormValue("username")
	if username == "" {
		errText := "Invalid form-data parameters"
		log.Error("%v", errText)
		http.Error(w, errText, http.StatusInternalServerError)
		return
	}

	userID, err := strconv.ParseInt(r.FormValue("userID"), 10, 64)
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

	// Prepare the response for a JSON object return
	proxy.prepareJSONResponse(w)

	// Parse the form-data to retrieve the `http.Request` information
	username := r.FormValue("username")
	credentials := r.FormValue("credentials")
	if username == "" || credentials == "" {
		errText := "Invalid form-data parameters"
		log.Error("%v", errText)
		http.Error(w, errText, http.StatusInternalServerError)
		return
	}

	userID, err := strconv.ParseInt(r.FormValue("userID"), 10, 64)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new `webauthnUser` struct from the input details
	wuser := db.NewWebauthnUser(userID, username, nil)

	// Load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r)
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
func (proxy *WebauthnFirewall) beginAttestation_base(
	query db.WebauthnQuery, clientExtensions protocol.AuthenticationExtensions,
	w http.ResponseWriter, r *http.Request) {

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

	// Prepare the response for a JSON object return
	proxy.prepareJSONResponse(w)

	// Retrieve the `userID` associated with the current session
	userID, err := userIDFromSession(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the form-data to retrieve the `http.Request` information
	authenticationText := r.FormValue("auth_text")
	if authenticationText == "" {
		errText := "Invalid form-data parameters"
		log.Error("%v", errText)
		http.Error(w, errText, http.StatusInternalServerError)
		return
	}

	// Set the transaction authentication extension
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = authenticationText

	proxy.beginAttestation_base(db.QueryByUserID(userID), extensions, w, r)
	return
}

func (proxy *WebauthnFirewall) beginLogin(w http.ResponseWriter, r *http.Request) {
	// Call the proxy preamble
	proxy.preamble(w, r)

	// Prepare the response for a JSON object return
	proxy.prepareJSONResponse(w)

	// Parse the form-data to retrieve the `http.Request` information
	username := r.FormValue("user_name")
	if username == "" {
		errText := "Invalid form-data parameters"
		log.Error("%v", errText)
		http.Error(w, errText, http.StatusInternalServerError)
		return
	}

	proxy.beginAttestation_base(db.QueryByUsername(username), nil, w, r)
	return
}

func (proxy *WebauthnFirewall) finishLogin(w http.ResponseWriter, r *http.Request) {
	// Call the proxy preamble
	proxy.preamble(w, r)

	// Instantiate a `RequestRefiller` since `r` will be read multiple times
	reqRefill, err := NewRequestRefiller(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the form-data to retrieve the `http.Request` information
	username := r.FormValue("user_name")
	assertion := r.FormValue("assertion")
	if username == "" || assertion == "" {
		errText := "Invalid form-data parameters"
		log.Error("%v", errText)
		http.Error(w, errText, http.StatusInternalServerError)
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
	reqRefill.Refill()

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

	// Retrieve the `userID` associated with the current session
	userID, err := userIDFromSession(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the form-data to retrieve the `http.Request` information
	assertion := r.FormValue("assertion")
	if assertion == "" {
		errText := "Invalid form-data parameters"
		log.Error("%v", errText)
		http.Error(w, errText, http.StatusInternalServerError)
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

func (proxy *WebauthnFirewall) deleteRepositoryHelper(r *http.Request) (protocol.AuthenticationExtensions, error) {
	// Get the `username` and `reponame` variables passed in the url
	// used for the transaction string verification
	vars := mux.Vars(r)
	username := vars["username"]
	reponame := vars["reponame"]

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = fmt.Sprintf("Confirm repository delete: %s/%s", username, reponame)

	return extensions, nil
}

func (proxy *WebauthnFirewall) repoSettings(w http.ResponseWriter, r *http.Request) {
	// Instantiate a `RequestRefiller` since `r` will be read multiple times
	reqRefill, err := NewRequestRefiller(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the form-data to retrieve the `http.Request` information
	action := r.FormValue("action")
	if action == "" {
		errText := "Invalid form-data parameters"
		log.Error("%v", errText)
		http.Error(w, errText, http.StatusInternalServerError)
		return
	}

	// Refill the `request` data before handling onward
	reqRefill.Refill()

	var handlerFn func(http.ResponseWriter, *http.Request)

	switch action {
	case "delete":
		// Handle deletion separately
		handlerFn = proxy.webauthnSecure(proxy.deleteRepositoryHelper)
	default:
		// Proxy all other requests
		handlerFn = proxy.proxyRequest
	}

	// Handle this request according to the set `handlerFn` function
	handlerFn(w, r)
	return
}

func (proxy *WebauthnFirewall) addSSHKey(r *http.Request) (protocol.AuthenticationExtensions, error) {
	sshKeyName := r.FormValue("title")
	if sshKeyName == "" {
		return nil, fmt.Errorf("Invalid form-data parameters")
	}

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = fmt.Sprintf("Add SSH key named: %v", sshKeyName)

	return extensions, nil
}

func (proxy *WebauthnFirewall) deleteSSHKey(r *http.Request) (protocol.AuthenticationExtensions, error) {
	// Get the full `sshKey` data from the `sshKeyID` located in the form
	sshKeyID, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		return nil, err
	}

	sshKey, err := sshKeyFromSSHKeyID(sshKeyID)
	if err != nil {
		return nil, err
	}

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = fmt.Sprintf("Delete SSH key named: %v", sshKey.Name)

	// Success!
	return extensions, nil
}

func (proxy *WebauthnFirewall) userProfileUpdate(r *http.Request) (protocol.AuthenticationExtensions, error) {
	// Parse the form-data to retrieve the `http.Request` information
	username := r.FormValue("name")
	email := r.FormValue("email")
	if username == "" || email == "" {
		return nil, fmt.Errorf("Invalid form-data parameters")
	}

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = fmt.Sprintf("Confirm profile details: username %v email %v", username, email)

	// Success!
	return extensions, nil
}

func (proxy *WebauthnFirewall) setPrimaryEmailHelper(r *http.Request) (protocol.AuthenticationExtensions, error) {
	// Get the full `email` data from the `emailID` located in the form
	emailID, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		return nil, err
	}

	email, err := emailFromEmailID(emailID)
	if err != nil {
		return nil, err
	}

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = fmt.Sprintf("Confirm new primary email: %v", email.Email)

	// Success!
	return extensions, nil
}

func (proxy *WebauthnFirewall) userSettingsEmail(w http.ResponseWriter, r *http.Request) {
	// Instantiate a `RequestRefiller` since `r` will be read multiple times
	reqRefill, err := NewRequestRefiller(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the form-data to retrieve the `http.Request` information
	action := r.FormValue("_method")

	// Refill the `request` data before handling onward
	reqRefill.Refill()

	var handlerFn func(http.ResponseWriter, *http.Request)

	switch action {
	case "PRIMARY":
		// Handle primary email separately
		handlerFn = proxy.webauthnSecure(proxy.setPrimaryEmailHelper)
	default:
		// Proxy all other requests
		handlerFn = proxy.proxyRequest
	}

	// Handle this request according to the set `handlerFn` function
	handlerFn(w, r)
	return
}

func (proxy *WebauthnFirewall) passwordChange(r *http.Request) (protocol.AuthenticationExtensions, error) {
	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = "Confirm password change"

	// Success!
	return extensions, nil
}

func (proxy *WebauthnFirewall) leaveRepository(r *http.Request) (protocol.AuthenticationExtensions, error) {
	// Get the full `repo` data from the `repoID` located in the form
	repoID, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		return nil, err
	}

	repo, err := repoFromRepoID(repoID)
	if err != nil {
		return nil, err
	}

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = fmt.Sprintf("Leave repository named: %v", repo.Name)

	// Success!
	return extensions, nil
}

func (proxy *WebauthnFirewall) deleteApplicationToken(r *http.Request) (protocol.AuthenticationExtensions, error) {
	// Get the full `appToken` data from the `appTokenID` located in the form
	appTokenID, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		return nil, err
	}

	// TODO: This is repeated. Already done in parent `webauthnSecure` function
	// Retrieve the `userID` associated with the current session
	userID, err := userIDFromSession(r)
	if err != nil {
		return nil, err
	}

	appToken, err := appTokenFromAppTokenID(userID, appTokenID)
	if err != nil {
		return nil, err
	}

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = fmt.Sprintf("Delete App named: %v", appToken.Name)

	// Success!
	return extensions, nil
}

func (proxy *WebauthnFirewall) publishNewRelease(r *http.Request) (protocol.AuthenticationExtensions, error) {
	// Parse the form-data to retrieve the `http.Request` information
	title := r.FormValue("title")
	if title == "" {
		return nil, fmt.Errorf("Invalid form-data parameters")
	}

	// Get the names of the `attachments` being uploaded
	uuids := r.Form["files"]
	attachments := make([]*Attachment, len(uuids))
	for idx, uuid := range uuids {
		// Retrieve the `Attachment` struct for the respective `uuid`
		attachment, err := attachmentFromAttachmentID(uuid)
		if err != nil {
			return nil, err
		}
		attachments[idx] = attachment
	}

	// Create the authentication text
	authText := fmt.Sprintf("Publish release named: %v!", title)

	// Only include the attachment `Name`s if they exist
	if len(attachments) != 0 {
		// Convert the `attachments` to a string to be displayed
		fileNames := make([]string, len(attachments))
		for idx, attachment := range attachments {
			fileNames[idx] = attachment.Name
		}

		authText += fmt.Sprintf("\nFile names: %s!", strings.Join(fileNames, ", "))
	}

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = authText

	// Success!
	return extensions, nil
}

// TODO: A lot of these functions can be put into their own files such as the registration, log in, txAuthn handlers, util functions
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
	r.HandleFunc("/webauthn/is_enabled/{user}", wfirewall.webauthnIsEnabled).Methods("GET")

	r.HandleFunc("/webauthn/begin_register", wfirewall.beginRegister).Methods("POST")
	r.HandleFunc("/webauthn/finish_register", wfirewall.finishRegister).Methods("POST")

	r.HandleFunc("/webauthn/begin_login", wfirewall.beginLogin).Methods("POST")
	r.HandleFunc("/user/login", wfirewall.finishLogin).Methods("POST")

	r.HandleFunc("/webauthn/begin_attestation", wfirewall.beginAttestation).Methods("POST")
	r.HandleFunc("/webauthn/disable", wfirewall.disableWebauthn).Methods("POST")

	r.HandleFunc("/{username}/{reponame}/settings", wfirewall.repoSettings).Methods("POST")
	r.HandleFunc("/user/settings/ssh", wfirewall.webauthnSecure(wfirewall.addSSHKey)).Methods("POST")
	r.HandleFunc("/user/settings/ssh/delete", wfirewall.webauthnSecure(wfirewall.deleteSSHKey)).Methods("POST")
	r.HandleFunc("/user/settings", wfirewall.webauthnSecure(wfirewall.userProfileUpdate)).Methods("POST")
	r.HandleFunc("/user/settings/email", wfirewall.userSettingsEmail).Methods("POST")
	r.HandleFunc("/user/settings/password", wfirewall.webauthnSecure(wfirewall.passwordChange)).Methods("POST")
	r.HandleFunc("/user/settings/repositories/leave", wfirewall.webauthnSecure(wfirewall.leaveRepository)).Methods("POST")
	r.HandleFunc("/user/settings/applications/delete", wfirewall.webauthnSecure(wfirewall.deleteApplicationToken)).Methods("POST")
	r.HandleFunc("/{username}/{repo}/releases/new", wfirewall.webauthnSecure(wfirewall.publishNewRelease)).Methods("POST")

	// Catch all other requests and simply proxy them onward
	r.PathPrefix("/").HandlerFunc(wfirewall.proxyRequest).Methods("GET", "POST")

	// Start up the server
	log.Info("Starting up server on port: %d", reverseProxyPort)
	log.Info("Forwarding HTTP: %d -> %d", reverseProxyPort, backendPort)

	log.Fatal("%v", http.ListenAndServeTLS(reverseProxyAddress, "server.crt", "server.key", r))

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
