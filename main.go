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

type Comment struct {
	ID   uint   `json:"id"`
	Body string `json:"body"`
}

func commentFromCommentID(slug string, commentID uint) (*Comment, error) {
	// Construct the URL to retrieve all of the comments for a given `slug`
	url := fmt.Sprintf("%s/api/articles/%s/comments", backendAddress, slug)

	var comments struct {
		Comments []Comment `json:"comments"`
	}

	err := tool.GetRequestJSON(url, &comments)
	if err != nil {
		return nil, err
	}

	// Search for the comment with `commentID`
	for _, comment := range comments.Comments {
		if comment.ID == commentID {
			return &comment, nil
		}
	}

	// Comment not found
	return nil, fmt.Errorf("Comment ID %d not found", commentID)
}

type Article struct {
	Slug  string `json:"slug"`
	Title string `json:"title"`
}

func articleFromArticleSlug(slug string) (*Article, error) {
	// Construct the URL to retrieve the article associated with `slug`
	url := fmt.Sprintf("%s/api/articles/%s", backendAddress, slug)

	var article struct {
		Article Article `json:"article"`
	}

	err := tool.GetRequestJSON(url, &article)
	if err != nil {
		return nil, err
	}

	// Success!
	return &article.Article, nil
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

	proxy.ModifyResponse = func(r *http.Response) error {
		// Change the access control origin for all responses
		// coming back from the reverse proxy server
		r.Header.Set("Access-Control-Allow-Origin", frontendAddress)
		return nil
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
		userID, err := userIDFromJWT(r)
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

			// Parse the JSON `http.Request`
			var reqBody struct {
				Assertion string `json:"assertion"`
			}

			err = json.NewDecoder(r.Body).Decode(&reqBody)
			if err != nil {
				log.Error("%v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
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
			err = checkWebauthnAssertion(r, db.QueryByUserID(userID), extensions, reqBody.Assertion)
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

	userID, err := userIDFromJWT(r)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new `webauthnUser` struct from the input details
	wuser := db.NewWebauthnUser(userID, reqBody.Username, nil)

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

	// Parse the JSON `http.Request`
	var reqBody struct {
		Username  string `json:"username"`
		Assertion string `json:"assertion"`
	}

	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	userID, err := userIDFromJWT(r)
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

	wcredential, err := webauthnAPI.FinishRegistration(wuser, sessionData, reqBody.Assertion)
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

	// Retrieve the `userID` associated with the current JWT
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

	// Prepare the response for a JSON object return
	proxy.prepareJSONResponse(w)

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
	// Call the proxy preamble
	proxy.preamble(w, r)

	// Instantiate a `RequestRefiller` since `r` will be read multiple times
	reqRefill, err := NewRequestRefiller(r)
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

	err = json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// See if the user has webauthn enabled
	isEnabled := db.WebauthnStore.IsUserEnabled(db.QueryByUsername(reqBody.User.Username))

	// Perform a webauthn check if webauthn is enabled for this user
	if isEnabled {
		// Check the webauthn assertion for this operation. There are no extensions to verify
		err = checkWebauthnAssertion(r, db.QueryByUsername(reqBody.User.Username), nil, reqBody.Assertion)
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

	// Prepare the response for a JSON object return
	proxy.prepareJSONResponse(w)

	// Retrieve the `userID` associated with the current JWT
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
	err = checkWebauthnAssertion(r, query, extensions, reqBody.Assertion)
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

func (proxy *WebauthnFirewall) deleteComment(r *http.Request) (protocol.AuthenticationExtensions, error) {
	// Extract the context info located in the URL
	vars := mux.Vars(r)
	slug := vars["slug"]
	commentID, err := strconv.ParseUint(vars["comment_id"], 10, 64)
	if err != nil {
		return nil, err
	}

	comment, err := commentFromCommentID(slug, uint(commentID))
	if err != nil {
		return nil, err
	}

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = fmt.Sprintf("Confirm comment delete: %v", comment.Body)

	// Success!
	return extensions, nil
}

func (proxy *WebauthnFirewall) deleteArticle(r *http.Request) (protocol.AuthenticationExtensions, error) {
	// Extract the context info located in the URL
	vars := mux.Vars(r)
	slug := vars["slug"]

	article, err := articleFromArticleSlug(slug)
	if err != nil {
		return nil, err
	}

	// Create the extension to verify against
	extensions := make(protocol.AuthenticationExtensions)
	extensions["txAuthSimple"] = fmt.Sprintf("Confirm article delete: Name %s", article.Title)

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

	// Infrastructure Webauthn routes
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

	// Webauthn secured routes
	r.HandleFunc("/api/articles/{slug}/comments/{comment_id}", wfirewall.optionsHandler("DELETE")).Methods("OPTIONS")
	r.HandleFunc("/api/articles/{slug}/comments/{comment_id}", wfirewall.webauthnSecure(wfirewall.deleteComment)).Methods("DELETE")

	r.HandleFunc("/api/articles/{slug}", wfirewall.optionsHandler("DELETE", "GET")).Methods("OPTIONS")
	r.HandleFunc("/api/articles/{slug}", wfirewall.webauthnSecure(wfirewall.deleteArticle)).Methods("DELETE")

	// Catch all other requests and simply proxy them onward
	r.PathPrefix("/api/").HandlerFunc(wfirewall.proxyRequest).Methods("OPTIONS", "GET", "POST", "PUT", "DELETE")

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
