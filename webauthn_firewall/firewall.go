package webauthn_firewall

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/gorilla/mux"
	log "unknwon.dev/clog/v2"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/db"

	"webauthn/webauthn"
	"webauthn_utils/session"
)

const (
	ENV_SESSION_KEY string = "SESSION_KEY"
)

var (
	webauthnAPI  *webauthn.WebAuthn
	sessionStore *session.Store
)

type getInputFnType func(r *ExtendedRequest, args ...string) (string, error)
type ContextGettersType map[string]func(...interface{}) (interface{}, error)

type WebauthnFirewall struct {
	*httputil.ReverseProxy

	// Public fields
	FrontendAddress     string
	BackendAddress      string
	ReverseProxyAddress string

	// Private fields
	router *mux.Router

	getUserID       func(*http.Request) (int64, error)
	getInputDefault getInputFnType
	contextGetters  ContextGettersType

	verbose bool
}

type WebauthnFirewallConfig struct {
	RPDisplayName string // Display Name for your site
	RPID          string // Generally the domain name for your site

	FrontendAddress     string
	BackendAddress      string
	ReverseProxyAddress string

	GetUserID       func(*http.Request) (int64, error)
	GetInputDefault getInputFnType
	ContextGetters  ContextGettersType

	LoginURL string

	Verbose bool
}

func NewWebauthnFirewall(config *WebauthnFirewallConfig) *WebauthnFirewall {
	// Initialize the Webauthn API code
	var err error
	webauthnAPI, err = webauthn.New(&webauthn.Config{
		RPDisplayName: config.RPDisplayName,
		RPID:          config.RPID,
		RPOrigin:      config.FrontendAddress, // Have the front-end be the origin URL for WebAuthn requests
	})
	if err != nil {
		panic("Unable to initialize Webauthn API: " + err.Error())
	}

	// Initialize the database for the firewall
	log.Info("Starting up database")
	if err = db.Init(); err != nil {
		panic("Unable to initialize database: " + err.Error())
	}

	origin, _ := url.Parse(config.BackendAddress)
	proxy := httputil.NewSingleHostReverseProxy(origin)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	proxy.ModifyResponse = func(r *http.Response) error {
		// Change the access control origin for all responses
		// coming back from the reverse proxy server
		r.Header.Set("Access-Control-Allow-Origin", config.FrontendAddress)
		return nil
	}

	// Construct and return the webauthn firewall
	wfirewall := &WebauthnFirewall{
		ReverseProxy: proxy,

		// Set the public fields
		FrontendAddress:     config.FrontendAddress,
		BackendAddress:      config.BackendAddress,
		ReverseProxyAddress: config.ReverseProxyAddress,

		// Set the private fields
		getUserID:       config.GetUserID,
		getInputDefault: config.GetInputDefault,
		contextGetters:  config.ContextGetters,

		verbose: config.Verbose,
	}

	// Set the router to the `wfirewall`
	wfirewall.router = mux.NewRouter()

	// Register the generic HTTP routes
	wfirewall.Secure("GET", "/webauthn/is_enabled/{user}", wfirewall.webauthnIsEnabled)

	wfirewall.Secure("POST", "/webauthn/begin_register", wfirewall.beginRegister)
	wfirewall.Secure("POST", "/webauthn/finish_register", wfirewall.finishRegister)

	wfirewall.Secure("POST", "/webauthn/begin_login", wfirewall.beginLogin)
	wfirewall.Secure("POST", config.LoginURL, wfirewall.finishLogin)

	wfirewall.Secure("POST", "/webauthn/begin_attestation", wfirewall.beginAttestation)
	wfirewall.Secure("POST", "/webauthn/disable", wfirewall.disableWebauthn)

	return wfirewall
}

func (wfirewall *WebauthnFirewall) Secure(method, url string, handleFn func(http.ResponseWriter, *ExtendedRequest)) {
	// Register the `url` and `method` with the HTTP router
	wfirewall.router.HandleFunc(url, wfirewall.wrapHandleFn(handleFn)).Methods(method)
}

func (wfirewall *WebauthnFirewall) ListenAndServeTLS(cert, key string) {
	// This function gets called once `wfirewall` has been entirely initialized.
	// Catch all remaining requests and simply proxy them onward
	wfirewall.router.PathPrefix("/").
		HandlerFunc(wfirewall.wrapHandleFn(wfirewall.proxyRequest)).
		Methods("OPTIONS", "GET", "POST", "PUT", "DELETE")

	// Start up the server
	log.Info("Starting up server on port: %s", wfirewall.ReverseProxyAddress)
	log.Info("Forwarding HTTP: %s -> %s", wfirewall.ReverseProxyAddress, wfirewall.BackendAddress)

	log.Fatal("%v", http.ListenAndServeTLS(wfirewall.ReverseProxyAddress, cert, key, wfirewall.router))
}

func init() {
	// Initialize the logger code
	err := log.NewConsole()
	if err != nil {
		panic("Unable to create new logger: " + err.Error())
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
