package main

import (
	"fmt"
	"net/http"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/tool"
	wf "github.com/JSmith-BitFlipper/webauthn-firewall-proxy/webauthn_firewall"

	log "unknwon.dev/clog/v2"
)

const (
	frontendPort     int = 8081
	backendPort      int = 3000
	reverseProxyPort int = 8081
)

type GogsFirewall struct {
	*wf.WebauthnFirewall
}

func userIDFromSession(wfirewall *wf.WebauthnFirewall, r *http.Request) (int64, error) {
	// Get the UserID associated with the sessionID in the cookies. This is to assure that the
	// server and the firewall are referencing the same user during the webauthn check
	url := fmt.Sprintf("%s/server_context/session2user", wfirewall.BackendAddress)
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

func main() {
	wfirewallConfigs := &wf.WebauthnFirewallConfig{
		RPDisplayName: "Foobar Corp.",
		RPID:          "localhost",

		FrontendAddress:     fmt.Sprintf("https://localhost:%d", frontendPort),
		BackendAddress:      fmt.Sprintf("https://localhost:%d", backendPort),
		ReverseProxyAddress: fmt.Sprintf("localhost:%d", reverseProxyPort),

		GetUserID:       userIDFromSession,
		GetInputDefault: wf.GetFormInput,

		LoginURL: "/user/login",

		Verbose: true,
	}

	// Initialize a new webauthn firewall
	wfirewall := wf.NewWebauthnFirewall(wfirewallConfigs)

	// wfirewall.Secure("POST", "/user/settings/ssh", wfirewall.Authn(
	// 	"Add SSH key named: %v",
	// 	wf.Get("title"),
	// ))

	wfirewall.ListenAndServeTLS("server.crt", "server.key")
}

func init() {
	// Initialize the logger code
	err := log.NewConsole()
	if err != nil {
		panic("Unable to create new logger: " + err.Error())
	}
}
