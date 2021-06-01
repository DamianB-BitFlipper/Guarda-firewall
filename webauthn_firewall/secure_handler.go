package webauthn_firewall

import (
	"fmt"
)

type FirewallSecureArgs interface{}

type customOptions struct {
	allowMethods []string
}

func CustomOptions(allowMethods ...string) customOptions {
	return customOptions{
		allowMethods: allowMethods,
	}
}

func NoOptions() customOptions {
	return CustomOptions()
}

func (wfirewall *WebauthnFirewall) Secure(method, url string, handleFn HandlerFnType, optArgs ...FirewallSecureArgs) {
	// Set the default `options` according to the `wfirewall.supplyOptions` flag
	options := NoOptions()
	if wfirewall.supplyOptions {
		options = CustomOptions(method)
	}

	// Run through the `optArgs` and process them
	for _, arg := range optArgs {
		switch arg.(type) {
		case customOptions:
			options = arg.(customOptions)
		default:
			panic(fmt.Sprintf("Unknown option argument in Secure: %v", arg))
		}
	}

	// Add the `allowMethods` to the OPTIONS of `url` if there are any
	if len(options.allowMethods) != 0 {
		optionsHandler := wfirewall.optionsHandler(options.allowMethods...)
		wfirewall.router.HandleFunc(url, wfirewall.wrapWithExtendedReq(optionsHandler)).Methods("OPTIONS")
	}

	// Register the `url` and `method` with the HTTP router
	wfirewall.router.HandleFunc(url, wfirewall.wrapWithExtendedReq(handleFn)).Methods(method)
}

// Alias function `Handle` to `Secure` for better code documentation. Some routes should
// still be handled by the firewall, but not necessarily webauthn secured
func (wfirewall *WebauthnFirewall) Handle(method, url string, handleFn HandlerFnType, optArgs ...FirewallSecureArgs) {
	wfirewall.Secure(method, url, handleFn, optArgs...)
	return
}
