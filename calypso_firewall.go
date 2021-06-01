package main

import (
	"fmt"
	"net/http"
	"strings"

	log "unknwon.dev/clog/v2"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/db"
	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/tool"
	wf "github.com/JSmith-BitFlipper/webauthn-firewall-proxy/webauthn_firewall"
)

// To forward 443 to 8081: sudo iptables -t nat -A OUTPUT -o lo -p tcp --dport 443 -j REDIRECT --to-port 8081
// Edited: about:config -> network.stricttransportsecurity.preloadlist to `true`

const (
	frontendPort     int = 3000
	reverseProxyPort int = 8081
)

var (
	frontendAddress       = fmt.Sprintf("https://calypso.localhost:%d", frontendPort)
	reverseProxyTargetMap = wf.NewProxyTarget("public-api.wordpress.com", "https://workaround-public-api.wordpress.com", wf.GetJSONInput).
				AnotherTarget("wordpress.com", "https://workaround.wordpress.com", wf.GetFormInput)
	reverseProxyAddress = fmt.Sprintf("localhost:%d", reverseProxyPort)
)

type CalypsoFirewall struct {
	*wf.WebauthnFirewall
}

func userIDFromSession(r *http.Request) (int64, error) {
	// Get the UserID associated with the sessionID in the cookies. This is to assure that the
	// server and the firewall are referencing the same user during the webauthn check
	apiHost := "https://public-api.wordpress.com"
	url := fmt.Sprintf("%s/rest/v1.1/me", apiHost)
	userIDReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	// Pass on the Authorization header from `r` to `userIDReq`
	authorizationString := r.Header.Get("Authorization")
	userIDReq.Header.Set("Authorization", authorizationString)

	for _, cookie := range r.Cookies() {
		userIDReq.AddCookie(cookie)
	}

	var sessionInfo struct {
		UserID int64 `json:"ID"`
	}
	err = tool.PerformRequestJSON(userIDReq, &sessionInfo)
	if err != nil {
		return 0, err
	}

	// Success!
	return sessionInfo.UserID, nil
}

func languageFromID(args ...interface{}) (interface{}, error) {
	// Sanity check the input
	if len(args) != 1 {
		return nil, fmt.Errorf("Language context expects 1 arguments, received: %v", args)
	}

	v := fmt.Sprintf("%v", args[0])

	// TODO: See if it is possible to do this with the wordpress API route
	//
	// Language IDs are hard coded in the front-end
	switch v {
	case "1":
		return "English", nil
	case "19":
		return "Espanol", nil
	default:
		return "", fmt.Errorf("Unrecognizable language ID %v", v)
	}
}

func privacySettingFromID(args ...interface{}) (interface{}, error) {
	// Sanity check the input
	if len(args) != 1 {
		return nil, fmt.Errorf("Privacy setting context expects 1 arguments, received: %v", args)
	}

	v := fmt.Sprintf("%v", args[0])

	// TODO: See if it is possible to do this with the wordpress API route
	//
	// Language IDs are hard coded in the front-end
	switch v {
	case "-1":
		return "Private", nil
	case "0":
		return "Coming Soon", nil
	case "1":
		return "Public", nil
	default:
		return "", fmt.Errorf("Unrecognizable privacy setting %v", v)
	}
}

func themeFromID(args ...interface{}) (interface{}, error) {
	// Sanity check the input
	if len(args) != 1 {
		return nil, fmt.Errorf("Theme context requires exactly 1 argument. Received: %v", args)
	}

	// Extract the `args` to meaningful variable names
	themeID := fmt.Sprintf("%v", args[0])

	// Construct the URL to retrieve the theme context
	apiHost := "https://public-api.wordpress.com"
	url := fmt.Sprintf("%s/rest/v1.2/themes/%s", apiHost, themeID)

	itemMap := make(wf.StructContext)
	err := tool.GetRequestJSON(url, &itemMap)
	if err != nil {
		return nil, err
	}

	// Success!
	return itemMap, nil
}

func (firewall *CalypsoFirewall) finishLogin(w http.ResponseWriter, r *wf.ExtendedRequest) {
	var handlerFn wf.HandlerFnType

	// Handle the different `action` accordingly
	action := r.GetURLParam("action")
	switch action {
	case "login-endpoint":
		handlerFn = func(w http.ResponseWriter, r *wf.ExtendedRequest) {
			// Get the username from the incoming login `http.Request`
			username := r.Get("username")
			assertion := r.Get("assertion")
			if r.HandleAnyErrors(w) {
				// Exit if there were any errors during the `Get` operations
				return
			}

			// See if the user has webauthn enabled
			isEnabled := db.WebauthnStore.IsUserEnabled(db.QueryByUsername(username))

			// Perform a webauthn check if webauthn is enabled for this user
			if isEnabled {
				// Check the webauthn assertion for this operation. There are no extensions to verify
				err := wf.CheckWebauthnAssertion(r, db.QueryByUsername(username), nil, assertion)
				if r.HandleError_WithStatus(w, err, http.StatusBadRequest) {
					return
				}
			}

			// Once the webauthn check passed, pass the request onward to
			// the server to check the username and password
			firewall.ProxyRequest(w, r)
			return
		}
	default:
		handlerFn = firewall.ProxyRequest
	}

	// Run the `handlerFn`
	handlerFn(w, r)
	return
}

func main() {
	// TODO: Add a flag to fall through (use / as a catch all) or not
	firewallConfigs := &wf.WebauthnFirewallConfig{
		RPDisplayName: "Foobar Corp.",
		RPID:          "calypso.localhost",

		FrontendAddress:       frontendAddress,
		ReverseProxyTargetMap: reverseProxyTargetMap,
		ReverseProxyAddress:   reverseProxyAddress,

		GetUserID: userIDFromSession,
		ContextGetters: wf.ContextGettersType{
			"language":        languageFromID,
			"privacy_setting": privacySettingFromID,
			"theme":           themeFromID,
		},

		WebauthnCorePrefix: "/webauthn",
		LoginURL:           "", // Use a custom `finishLogin` function
		LoginGetUsername:   nil,

		SupplyOptions: true,
		Verbose:       true,
	}

	// Initialize a new webauthn firewall as a `CalypsoFirewall` to be able to add custom methods
	firewall := CalypsoFirewall{wf.NewWebauthnFirewall(firewallConfigs)}

	// Serve a some HTML for iframe access to authorization cookies
	firewall.Handle("GET", "/wp-admin/rest-proxy/iframe/get_authorization_cookie.html", func(w http.ResponseWriter, r *wf.ExtendedRequest) {
		http.ServeFile(w, r.Request, "calypso_resources/get_authorization_cookie.html")
	})

	// Implement the custom `finishLogin` function
	firewall.Secure("POST", "/wp-login.php", firewall.finishLogin)

	firewall.Secure("POST", "/rest/{version}/sites/{site_id}/settings", firewall.Authn(
		"Save the profile settings: %v %v",
		wf.SetContextVar("language", wf.Get("lang_id")),
		wf.GetVar("language"),
		wf.SetContextVar("privacy_setting", wf.Get("blog_public")),
		wf.GetVar("privacy_setting"),
	))

	firewall.Secure("POST", "/rest/{version}/sites/{site_id}/invites/new", firewall.Authn(
		"Invite new user(s): %v",
		wf.Apply(func(args ...interface{}) (interface{}, error) {
			inviteesArg := args[0].([]interface{})
			invitees := make([]string, len(inviteesArg))

			for i, invitee := range inviteesArg {
				invitees[i] = fmt.Sprintf("%v", invitee)
			}
			return strings.Join(invitees, ","), nil
		}, wf.GetArray("invitees")),
	))

	firewall.Secure("POST", "/wpcom/{version}/sites/{site_id}/site-address-change", firewall.Authn(
		"Change site address\n\tfrom: %v\n\tto: %v.%v",
		wf.Get("old_domain"),
		wf.Get("blogname"),
		wf.Get("domain"),
	))

	firewall.Secure("POST", "/rest/{version}/sites/{site_id}/themes/mine", firewall.Authn(
		"Change theme to: %v",
		wf.SetContextVar("theme", wf.Get("theme")),
		wf.GetVar("theme").SubField("name"),
	))

	firewall.ListenAndServeTLS("server.crt", "server.key")
}

func init() {
	// Initialize the logger code
	err := log.NewConsole()
	if err != nil {
		panic("Unable to create new logger: " + err.Error())
	}
}
