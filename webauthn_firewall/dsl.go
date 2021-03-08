package webauthn_firewall

import (
	"fmt"
	"net/http"
)

// TODO: Have the ops return structs that implement the same function that
// gets the lexical scope and (optionally) sets a format array for the fomat placeholders
//
// Can chain calls to a struct, as long as last call returns a struct that implements this function

type scopeContainer map[string]interface{}

type dslInterface interface {
	execute(r *ExtendedRequest, scope scopeContainer, formatVars *[]interface{})
}

type getInput struct {
	fields     []string
	getInputFn getInputFnType
}

func (g getInput) execute(r *ExtendedRequest, _ scopeContainer, formatVars *[]interface{}) {
	val, err := g.getInputFn(r, g.fields...)
	if err != nil {
		// Set the current `r.err`
		r.err = err
		return
	}

	// Since this is a `get` operation, it should append to the `formatVars`
	*formatVars = append(*formatVars, val)
}

// Make sure `getInput` implements `dslInterface`
var _ dslInterface = getInput{}

func Get(fields ...string) getInput {
	return getInput{
		fields: fields,
		getInputFn: func(r *ExtendedRequest, args ...string) (string, error) {
			// Use the default function from the `ExtendedRequest`
			return r.getInputDefault(r, args...)
		},
	}
}

func (wfirewall *WebauthnFirewall) Authn(formatString string, ops ...dslInterface) func(http.ResponseWriter, *ExtendedRequest) {
	getAuthnText := func(r *ExtendedRequest) string {
		scope := make(scopeContainer)
		formatVars := make([]interface{}, 0)

		// Iterate through and execute the operations
		for _, op := range ops {
			// If an error was encountered, stop the execution
			if r.err != nil {
				return ""
			}

			op.execute(r, scope, &formatVars)
		}

		// Apply the `formatVars` to the `formatString`
		return fmt.Sprintf(formatString, formatVars...)
	}

	return wfirewall.webauthnSecure(getAuthnText)
}
