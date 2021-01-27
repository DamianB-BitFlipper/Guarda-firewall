package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/mux"
	log "unknwon.dev/clog/v2"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/db"
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

type WebauthnFirewall struct {
	*httputil.ReverseProxy
}

func logRequest(r *http.Request) {
	log.Info("%s:\t%s", r.Method, r.URL)
}

func (proxy *WebauthnFirewall) proxyRequest(w http.ResponseWriter, r *http.Request) {
	if verbose {
		logRequest(r)
	}

	proxy.ServeHTTP(w, r)
}

func (proxy *WebauthnFirewall) optionsHandler(allowMethods ...string) func(w http.ResponseWriter, r *http.Request) {
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

func (proxy *WebauthnFirewall) beginRegister(w http.ResponseWriter, r *http.Request) {
	if verbose {
		logRequest(r)
	}
	// Set the header info
	w.Header().Set("Access-Control-Allow-Origin", frontendAddress)
	w.Header().Set("Access-Control-Allow-Credentials", "true") // Allow transmitting cookies, used by `sessionStore`
	w.Header().Set("Content-Type", "application/json")

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

	// Get a `webauthnUser` for the requested username
	wuser, err := db.WebauthnStore.GetWebauthnUser(reqBody.Username)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

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

	// TODO: Make DB log same format as rest of firewall
	// Remove is_webauthn_enabled code from the backed to exclusively the firewall
	//
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
	if verbose {
		logRequest(r)
	}
	// Set the header info
	w.Header().Set("Access-Control-Allow-Origin", frontendAddress)
	w.Header().Set("Access-Control-Allow-Credentials", "true") // Allow transmitting cookies, used by `sessionStore`
	w.Header().Set("Content-Type", "application/json")

	// Parse the JSON `http.Request`
	var reqBody struct {
		Username   string `json:"username"`
		Assertion  string `json:"assertion"`
		RedirectTo string `json:"redirect_to"`
	}

	err := json.NewDecoder(r.Body).Decode(&reqBody)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get a `webauthnUser` for the requested username
	wuser, err := db.WebauthnStore.GetWebauthnUser(reqBody.Username)
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

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
	db.WebauthnStore.Create(wuser.WebAuthnName(), *credential)

	// Marshal a response `redirectTo` url
	json_response, err := json.Marshal(map[string]string{"redirectTo": reqBody.RedirectTo})
	if err != nil {
		log.Error("%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the `json_response`
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)
}

func main() {
	origin, _ := url.Parse(backendAddress)

	director := func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", origin.Host)
		req.URL.Scheme = "http"
		req.URL.Host = origin.Host
	}

	// Initialize a webauthn firewall
	wfirewall := &WebauthnFirewall{
		&httputil.ReverseProxy{Director: director},
	}

	// Initialize the database for the firewall
	log.Info("Starting up database")
	if err := db.Init(); err != nil {
		panic("Unable to initialize database: " + err.Error())
	}

	// Register the HTTP routes
	r := mux.NewRouter()

	// Proxy methods
	r.HandleFunc("/api/user", wfirewall.proxyRequest).Methods("OPTIONS", "GET", "POST")
	r.HandleFunc("/api/users/login", wfirewall.proxyRequest).Methods("OPTIONS", "POST")
	r.HandleFunc("/api/tags", wfirewall.proxyRequest).Methods("OPTIONS", "GET")
	r.HandleFunc("/api/profiles/{user}", wfirewall.proxyRequest).Methods("OPTIONS", "GET")
	r.HandleFunc("/api/articles/feed", wfirewall.proxyRequest).Methods("OPTIONS", "GET")
	r.HandleFunc("/api/articles", wfirewall.proxyRequest).Methods("OPTIONS", "GET", "POST")
	r.HandleFunc("/api/articles/{user}", wfirewall.proxyRequest).Methods("OPTIONS", "GET", "DELETE")
	r.HandleFunc("/api/articles/{user}/comments", wfirewall.proxyRequest).Methods("OPTIONS", "GET")

	// Webauthn methods
	r.HandleFunc("/api/webauthn/begin_register", wfirewall.optionsHandler("POST")).Methods("OPTIONS")
	r.HandleFunc("/api/webauthn/begin_register", wfirewall.beginRegister).Methods("POST")

	r.HandleFunc("/api/webauthn/finish_register", wfirewall.optionsHandler("POST")).Methods("OPTIONS")
	r.HandleFunc("/api/webauthn/finish_register", wfirewall.finishRegister).Methods("POST")

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
