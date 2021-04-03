package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"github.com/JSmith-BitFlipper/webauthn-firewall-proxy/tool"
	wf "github.com/JSmith-BitFlipper/webauthn-firewall-proxy/webauthn_firewall"

	log "unknwon.dev/clog/v2"
)

const (
	frontendPort     int = 4100
	backendPort      int = 8080
	reverseProxyPort int = 8081
)

var (
	frontendAddress     string = fmt.Sprintf("https://localhost:%d", frontendPort)
	backendAddress      string = fmt.Sprintf("http://localhost:%d", backendPort)
	reverseProxyAddress string = fmt.Sprintf("localhost:%d", reverseProxyPort)
)

type ConduitFirewall struct {
	*wf.WebauthnFirewall
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

func commentFromCommentID(args ...interface{}) (interface{}, error) {
	// Sanity check the input
	if len(args) != 2 {
		return nil, fmt.Errorf("Comment context requires exactly 2 arguments. Received: %v", args)
	}

	// Extract the `args` to meaningful variable names
	slug, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("Failed casing slug to string: %v", args[0])
	}

	commentID, ok := args[1].(int64)
	if !ok {
		return nil, fmt.Errorf("Failed casing commentID to int64: %v", args[1])
	}

	// Construct the URL to retrieve all of the comments for a given `slug`
	url := fmt.Sprintf("%s/api/articles/%s/comments", backendAddress, slug)

	var comments struct {
		Comments []wf.StructContext `json:"comments"`
	}

	err := tool.GetRequestJSON(url, &comments)
	if err != nil {
		return nil, err
	}

	// Search for the comment with `commentID`
	for _, comment := range comments.Comments {
		// The `comment["id"]` gets JSON decoded as a float64 cast to an interface
		if int64(comment["id"].(float64)) == commentID {
			return comment, nil
		}
	}

	// Comment not found
	return nil, fmt.Errorf("Comment ID %d not found", commentID)
}

func articleFromArticleSlug(args ...interface{}) (interface{}, error) {
	// Sanity check the input
	if len(args) != 1 {
		return nil, fmt.Errorf("Article context requires exactly 1 argument. Received: %v", args)
	}

	// Extract the `args` to meaningful variable names
	slug, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("Failed casing slug to string: %v", args[0])
	}

	// Construct the URL to retrieve the article associated with `slug`
	url := fmt.Sprintf("%s/api/articles/%s", backendAddress, slug)

	itemMap := make(wf.StructContext)
	err := tool.GetRequestJSON(url, &itemMap)
	if err != nil {
		return nil, err
	}

	// Success!
	return itemMap["article"], nil
}

func getCurrentUser(args ...interface{}) (interface{}, error) {
	// Sanity check the input
	if len(args) != 1 {
		return nil, fmt.Errorf("Current user context requires exactly 1 argument. Received: %v", args)
	}

	// Extract the `args` to meaningful variable names
	r, ok := args[0].(*wf.ExtendedRequest)
	if !ok {
		return nil, fmt.Errorf("Failed casing request to *wf.ExtendedRequest: %v", args[0])
	}

	// Construct the URL to retrieve the article associated with `slug`
	url := fmt.Sprintf("%s/api/user", backendAddress)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Copy over the JWT token located in the `Authorization` header
	authorizationString := r.Request.Header.Get("Authorization")
	req.Header.Set("Authorization", authorizationString)

	itemMap := make(wf.StructContext)
	err = tool.PerformRequestJSON(req, &itemMap)
	if err != nil {
		return nil, err
	}

	// Success!
	return itemMap["user"], nil
}

func (firewall *ConduitFirewall) updateUser(w http.ResponseWriter, r *wf.ExtendedRequest) {
	_currentUser := r.GetContext("current_user", r)
	if r.HandleAnyErrors(w) {
		// Exit if there were any errors during the `GetContext`
		return
	}
	currentUser := _currentUser.(wf.StructContext)

	// Begin with no `authnText`
	useAuthn := false
	authnText := ""
	var handlerFn wf.HandlerFnType

	// Only use authentication if the username, email or password are being changed
	if r.Get("user", "username") != currentUser["username"] ||
		r.Get("user", "email") != currentUser["email"] ||
		r.IgnoreError(r.Get, "user", "password") != "" {

		// TODO: Include the password somehow in the authentication text
		useAuthn = true
		authnText = fmt.Sprintf("Confirm new user details:\n\tusername %s\n\temail %s",
			r.Get("user", "username"),
			r.Get("user", "email"),
		)
	}

	if useAuthn {
		handlerFn = firewall.Authn(authnText)
	} else {
		handlerFn = firewall.ProxyRequest
	}

	// Run the `handlerFn`
	handlerFn(w, r)
	return
}

func main() {
	firewallConfigs := &wf.WebauthnFirewallConfig{
		RPDisplayName: "Foobar Corp.",
		RPID:          "localhost",

		FrontendAddress: frontendAddress,
		ReverseProxyTargetMap: map[string]string{
			reverseProxyAddress: backendAddress,
		},
		ReverseProxyAddress: reverseProxyAddress,

		GetUserID:       userIDFromJWT,
		GetInputDefault: wf.GetJSONInput,
		ContextGetters: wf.ContextGettersType{
			"comment":      commentFromCommentID,
			"article":      articleFromArticleSlug,
			"current_user": getCurrentUser,
		},

		WebauthnCorePrefix: "/api/webauthn",
		LoginURL:           "/api/users/login",
		LoginGetUsername: func(r *wf.ExtendedRequest) (string, error) {
			return r.Get_WithErr("user", "username")
		},

		SupplyOptions: true,
		Verbose:       true,
	}

	// Initialize a new webauthn firewall as a `ConduitFirewall` to be able to add custom methods
	firewall := ConduitFirewall{wf.NewWebauthnFirewall(firewallConfigs)}

	firewall.Secure("DELETE", "/api/articles/{slug}/comments/{comment_id}", firewall.Authn(
		"Confirm comment delete: %v",
		wf.SetContextVar("comment", wf.Get_URL("slug"), wf.GetInt64_URL("comment_id")),
		wf.GetVar("comment").SubField("body"),
	))

	firewall.Secure("DELETE", "/api/articles/{slug}", firewall.Authn(
		"Confirm article delete: Name %v",
		wf.SetContextVar("article", wf.Get_URL("slug")),
		wf.GetVar("article").SubField("title"),
	), wf.CustomOptions("DELETE", "GET"))

	firewall.Secure("PUT", "/api/user", firewall.updateUser, wf.CustomOptions("GET", "PUT"))

	firewall.ListenAndServeTLS("server.crt", "server.key")
}

func init() {
	// Initialize the logger code
	err := log.NewConsole()
	if err != nil {
		panic("Unable to create new logger: " + err.Error())
	}
}
