package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	log "unknwon.dev/clog/v2"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/db"
)

type WebauthnFirewall struct {
	*httputil.ReverseProxy
}

func logRequest(r *http.Request) {
	log.Info("%s:\t%s", r.Method, r.URL)
}

func (proxy *WebauthnFirewall) handleRequest(verbose bool) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if verbose {
			logRequest(r)
		}

		proxy.ServeHTTP(w, r)
	}
}

func main() {
	reverseProxyPort := 8081
	originPort := 8080
	origin, _ := url.Parse(fmt.Sprintf("http://localhost:%d/", originPort))

	director := func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", origin.Host)
		req.URL.Scheme = "http"
		req.URL.Host = origin.Host
	}

	// Initialize a webauthn firewall
	firewall := &WebauthnFirewall{
		&httputil.ReverseProxy{Director: director},
	}

	// Initialize the database for the firewall
	log.Info("Starting up database")
	firewallDB := db.New()
	if err := db.AutoMigrate(firewallDB); err != nil {
		panic("Unable to migrate database: " + err.Error())
	}

	http.HandleFunc("/api/", firewall.handleRequest(true))

	log.Info("Starting up server on port: %d", reverseProxyPort)
	log.Info("Forwarding HTTP: %d -> %d", reverseProxyPort, originPort)

	log.Fatal("%v", http.ListenAndServe(fmt.Sprintf(":%d", reverseProxyPort), nil))

	// Graceful stopping all loggers before exiting the program.
	log.Stop()
}

func init() {
	err := log.NewConsole()
	if err != nil {
		panic("Unable to create new logger: " + err.Error())
	}
}
