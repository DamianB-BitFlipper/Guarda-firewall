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

type HandlerFnType func(http.ResponseWriter, *ExtendedRequest)
type ContextGettersType map[string]func(...interface{}) (interface{}, error)

type targetTuple struct {
	destination     string
	getInputDefault getInputFnType
}
type proxyTargetMap map[string]targetTuple

func NewProxyTarget(src, dest string, getInputDefault getInputFnType) proxyTargetMap {
	target := targetTuple{
		destination:     dest,
		getInputDefault: getInputDefault,
	}

	return proxyTargetMap{src: target}
}

func (p proxyTargetMap) AnotherTarget(src, dest string, getInputDefault getInputFnType) proxyTargetMap {
	target := targetTuple{
		destination:     dest,
		getInputDefault: getInputDefault,
	}

	// Add the `target` to `p` and return
	p[src] = target
	return p
}

type WebauthnFirewall struct {
	reverseProxies map[string]*httputil.ReverseProxy

	// Public fields
	FrontendAddress       string
	ReverseProxyTargetMap proxyTargetMap
	ReverseProxyAddress   string

	// Private fields
	router *mux.Router

	getUserID      func(*http.Request) (int64, error)
	contextGetters ContextGettersType

	loginGetUsername func(*ExtendedRequest) (string, error)

	supplyOptions bool
	verbose       bool
}

type WebauthnFirewallConfig struct {
	RPDisplayName string // Display Name for your site
	RPID          string // Generally the domain name for your site

	FrontendAddress       string
	ReverseProxyTargetMap proxyTargetMap
	ReverseProxyAddress   string

	GetUserID      func(*http.Request) (int64, error)
	ContextGetters ContextGettersType

	WebauthnCorePrefix string
	LoginURL           string
	LoginGetUsername   func(*ExtendedRequest) (string, error)

	SupplyOptions bool
	Verbose       bool
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

	// Construct and return the webauthn firewall
	wfirewall := &WebauthnFirewall{
		// Set the public fields
		FrontendAddress:       config.FrontendAddress,
		ReverseProxyTargetMap: config.ReverseProxyTargetMap,
		ReverseProxyAddress:   config.ReverseProxyAddress,

		// Set the private fields
		getUserID:      config.GetUserID,
		contextGetters: config.ContextGetters,

		loginGetUsername: config.LoginGetUsername,

		supplyOptions: config.SupplyOptions,
		verbose:       config.Verbose,
	}

	// Create a new `ReverseProxy` for every `backendAddress`
	wfirewall.reverseProxies = make(map[string]*httputil.ReverseProxy)

	for host, target := range config.ReverseProxyTargetMap {
		forwardTo, err := url.Parse(target.destination)
		if err != nil {
			panic(fmt.Sprintf("Unable to parse URL: %s", target.destination))
		}

		proxy := httputil.NewSingleHostReverseProxy(forwardTo)
		proxy.Transport = &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}

		proxy.ModifyResponse = func(resp *http.Response) error {
			// Change the access control origin for all responses
			// coming back from the reverse proxy server
			resp.Header.Set("Access-Control-Allow-Origin", config.FrontendAddress)

			return nil
		}

		wfirewall.reverseProxies[host] = proxy
	}

	// Set the router to the `wfirewall`
	wfirewall.router = mux.NewRouter()

	// Register the generic HTTP routes
	wfirewall.Secure("GET", fmt.Sprintf("%s/is_enabled/{user}", config.WebauthnCorePrefix), wfirewall.webauthnIsEnabled)

	wfirewall.Secure("POST", fmt.Sprintf("%s/begin_register", config.WebauthnCorePrefix), wfirewall.beginRegister)
	wfirewall.Secure("POST", fmt.Sprintf("%s/finish_register", config.WebauthnCorePrefix), wfirewall.finishRegister)

	wfirewall.Secure("POST", fmt.Sprintf("%s/begin_login", config.WebauthnCorePrefix), wfirewall.beginLogin)

	// Use the provided `finishLogin` function under the user's discretion
	if config.LoginURL != "" {
		wfirewall.Secure("POST", config.LoginURL, wfirewall.finishLogin)
	}

	wfirewall.Secure("POST", fmt.Sprintf("%s/begin_attestation", config.WebauthnCorePrefix), wfirewall.beginAttestation)
	wfirewall.Secure("POST", fmt.Sprintf("%s/disable", config.WebauthnCorePrefix), wfirewall.disableWebauthn)

	return wfirewall
}

func (wfirewall *WebauthnFirewall) ListenAndServeTLS(cert, key string) {
	// This function gets called once `wfirewall` has been entirely initialized.
	// Catch all remaining requests and simply proxy them onward
	wfirewall.router.PathPrefix("/").
		HandlerFunc(wfirewall.wrapWithExtendedReq(wfirewall.proxyRequest)).
		Methods("OPTIONS", "GET", "POST", "PUT", "DELETE")

	// Start up the server
	log.Info("Starting up server on port: %s", wfirewall.ReverseProxyAddress)
	log.Info("Forwarding HTTP: %s -> %v", wfirewall.ReverseProxyAddress, wfirewall.ReverseProxyTargetMap)

	log.Fatal("%v", http.ListenAndServeTLS(wfirewall.ReverseProxyAddress, cert, key, wfirewall.router))
}

func (wfirewall *WebauthnFirewall) ServeHTTP(w http.ResponseWriter, r *ExtendedRequest) {
	host := r.Request.Host

	if proxy, ok := wfirewall.reverseProxies[host]; ok {
		proxy.ServeHTTP(w, r.Request)
		return
	}
	w.Write([]byte("403: Host forbidden " + host))
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
