package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
	log "unknwon.dev/clog/v2"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/db"
	"webauthn/webauthn"
)

var (
	reverseProxyPort int = 8081
	originPort       int = 8080
	webauthnAPI      *webauthn.WebAuthn
	verbose          bool = true
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
		w.Header().Set("Access-Control-Allow-Origin", "*")

		w.WriteHeader(http.StatusNoContent)
	}
}

func (proxy *WebauthnFirewall) beginRegister(w http.ResponseWriter, r *http.Request) {
	if verbose {
		logRequest(r)
	}
	// Set the header info
	w.Header().Set("Access-Control-Allow-Origin", "*")
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	// TODO: Save the `sessionData`
	log.Info("Session Data: %+v", sessionData)

	// Return the `json_response`
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)
}

func main() {
	origin, _ := url.Parse(fmt.Sprintf("http://localhost:%d/", originPort))

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

	// Start up the server
	log.Info("Starting up server on port: %d", reverseProxyPort)
	log.Info("Forwarding HTTP: %d -> %d", reverseProxyPort, originPort)

	// TODO: Make this TLS
	log.Fatal("%v", http.ListenAndServe(fmt.Sprintf(":%d", reverseProxyPort), r))

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
		RPDisplayName: "Foobar Corp.",                                        // Display Name for your site
		RPID:          "localhost",                                           // Generally the domain name for your site
		RPOrigin:      fmt.Sprintf("https://localhost:%d", reverseProxyPort), // The origin URL for WebAuthn requests
	})
	if err != nil {
		panic("Unable to initialize Webauthn API: " + err.Error())
	}

}
