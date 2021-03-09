package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/tool"
	wf "github.com/JSmith-BitFlipper/webauthn-firewall-proxy/webauthn_firewall"

	log "unknwon.dev/clog/v2"
)

const (
	frontendPort     int = 8081
	backendPort      int = 3000
	reverseProxyPort int = 8081
)

var (
	frontendAddress     string = fmt.Sprintf("https://localhost:%d", frontendPort)
	backendAddress      string = fmt.Sprintf("https://localhost:%d", backendPort)
	reverseProxyAddress string = fmt.Sprintf("localhost:%d", reverseProxyPort)
)

type GogsFirewall struct {
	*wf.WebauthnFirewall
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

func itemFromIDs(itemType string, nargs int) func(...interface{}) (interface{}, error) {
	return func(args ...interface{}) (interface{}, error) {
		// Sanity check the input
		if len(args) != nargs {
			return nil, fmt.Errorf("%s context expects %d arguments, received: %v", itemType, nargs, args)
		}

		// Format the URL arguments as strings
		urlArgs := make([]string, len(args))
		for idx, v := range args {
			urlArgs[idx] = fmt.Sprintf("%v", v)
		}

		// Construct the 'itemMap' and URL to retrieve the item from the input item `args`
		itemMap := make(wf.StructContext)
		url := fmt.Sprintf("%s/server_context/%s/%s", backendAddress, itemType, strings.Join(urlArgs, "/"))
		err := tool.GetRequestJSON(url, &itemMap)

		return itemMap, err
	}
}

func main() {
	firewallConfigs := &wf.WebauthnFirewallConfig{
		RPDisplayName: "Foobar Corp.",
		RPID:          "localhost",

		FrontendAddress:     frontendAddress,
		BackendAddress:      backendAddress,
		ReverseProxyAddress: reverseProxyAddress,

		GetUserID:       userIDFromSession,
		GetInputDefault: wf.GetFormInput,
		ContextGetters: wf.ContextGettersType{
			"ssh_key":   itemFromIDs("ssh_key", 1),
			"repo":      itemFromIDs("repository", 1),
			"app_token": itemFromIDs("app_token", 2),
			"webhook":   itemFromIDs("repo_webhook", 3),
		},

		LoginURL: "/user/login",

		Verbose: true,
	}

	// Initialize a new webauthn firewall as a `GogsFirewall` to be able to add custom methods
	firewall := GogsFirewall{wf.NewWebauthnFirewall(firewallConfigs)}

	// firewall.Secure("POST", "/{username}/{reponame}/settings", firewall.repoSettings)

	firewall.Secure("POST", "/user/settings/ssh", firewall.Authn(
		"Add SSH key named: %v",
		wf.Get("title"),
	))

	firewall.Secure("POST", "/user/settings/ssh/delete", firewall.Authn(
		"Delete SSH key named: %v",
		wf.SetContextVar("ssh_key", wf.Get("id")),
		wf.GetVar("ssh_key").SubField("Name"),
	))

	firewall.Secure("POST", "/user/settings", firewall.Authn(
		"Confirm profile details: username %v email %v",
		wf.Get("name"),
		wf.Get("email"),
	))

	// wfirewall.Secure("POST", "/user/settings/email", wfirewall.userSettingsEmail)

	firewall.Secure("POST", "/user/settings/password", firewall.Authn(
		"Confirm password change",
	))

	firewall.Secure("POST", "/user/settings/repositories/leave", firewall.Authn(
		"Leave repository named: %v",
		wf.SetContextVar("repo", wf.Get("id")),
		wf.GetVar("repo").SubField("Name"),
	))

	firewall.Secure("POST", "/user/settings/applications/delete", firewall.Authn(
		"Delete App named: %v",
		wf.SetContextVar("app_token", wf.GetUserID(), wf.Get("id")),
		wf.GetVar("app_token").SubField("Name"),
	))

	// wfirewall.Secure("POST", "/{username}/{repo}/releases/new", wfirewall.publishNewRelease)

	firewall.Secure("POST", "/{username}/{repo}/settings/hooks/delete", firewall.Authn(
		"Delete webhook for: URL %v",
		wf.SetContextVar("webhook", wf.Get_URL("username"), wf.Get_URL("repo"), wf.Get("id")),
		wf.GetVar("webhook").SubField("URL"),
	))

	// An exmaple of the extend of this DSL. Equivalent to above
	//
	// firewall.Secure("POST", "/{username}/{repo}/settings/hooks/delete", firewall.Authn(
	// 	"Delete webhook for: URL %v",
	// 	wf.SetVar("username", wf.Get_URL("username")),
	// 	wf.SetVar("repo", wf.Get_URL("repo")),
	// 	wf.SetVar("id", wf.Get("id")),
	// 	wf.SetVar("webhook", wf.GetContext("webhook", wf.GetVar("username"), wf.GetVar("repo"), wf.GetVar("id"))),
	// 	wf.GetVar("webhook").SubField("URL"),
	// ))

	firewall.ListenAndServeTLS("server.crt", "server.key")
}

func init() {
	// Initialize the logger code
	err := log.NewConsole()
	if err != nil {
		panic("Unable to create new logger: " + err.Error())
	}
}
