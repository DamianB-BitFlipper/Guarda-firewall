package main

import (
	"fmt"
	"net/http"

	// "github.com/JSmith-BitFlipper/webauthn-firewall-proxy/tool"
	wf "github.com/JSmith-BitFlipper/webauthn-firewall-proxy/webauthn_firewall"

	log "unknwon.dev/clog/v2"
)

const (
	frontendPort int = 3000
	// To forward 443 to 8081: sudo iptables -t nat -A OUTPUT -o lo -p tcp --dport 443 -j REDIRECT --to-port 8081
	reverseProxyPort int = 8081
)

var (
	frontendAddress string            = fmt.Sprintf("https://calypso.localhost:%d", frontendPort)
	hostTargetMap   map[string]string = map[string]string{
		"public-api.wordpress.com": "https://workaround-public-api.wordpress.com",
	}
	reverseProxyAddress string = fmt.Sprintf("localhost:%d", reverseProxyPort)
)

type CalypsoFirewall struct {
	*wf.WebauthnFirewall
}

func userIDFromSession(_ *http.Request) (int64, error) {
	// TODO
	return 0, nil
}

func main() {
	firewallConfigs := &wf.WebauthnFirewallConfig{
		RPDisplayName: "Foobar Corp.",
		RPID:          "calypso.localhost",

		FrontendAddress:       frontendAddress,
		ReverseProxyTargetMap: hostTargetMap,
		ReverseProxyAddress:   reverseProxyAddress,

		GetUserID:       userIDFromSession,
		GetInputDefault: wf.GetJSONInput,
		ContextGetters:  wf.ContextGettersType{},

		WebauthnCorePrefix: "/webauthn",
		LoginURL:           "/user/login",
		LoginGetUsername: func(r *wf.ExtendedRequest) (string, error) {
			return r.Get_WithErr("user_name")
		},

		SupplyOptions: false,
		Verbose:       true,
	}

	// Initialize a new webauthn firewall as a `CalypsoFirewall` to be able to add custom methods
	firewall := CalypsoFirewall{wf.NewWebauthnFirewall(firewallConfigs)}

	firewall.ListenAndServeTLS("server.crt", "server.key")
}

func init() {
	// Initialize the logger code
	err := log.NewConsole()
	if err != nil {
		panic("Unable to create new logger: " + err.Error())
	}
}
