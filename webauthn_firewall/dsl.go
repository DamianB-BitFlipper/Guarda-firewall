package webauthn_firewall

import (
	"fmt"
	"net/http"

	log "unknwon.dev/clog/v2"
)

type scopeContainer map[string]interface{}
type StructContext = scopeContainer

type dslInterface interface {
	// Retrieves the result of an operation
	retrieve(r *ExtendedRequest, scope scopeContainer) interface{}

	// Applies the operation to the `scope` and `formatVars`
	execute(r *ExtendedRequest, scope scopeContainer, formatVars *[]interface{})
}

type getInput struct {
	fields     []string
	getInputFn getInputFnType
}

func (g getInput) retrieve(r *ExtendedRequest, _ scopeContainer) interface{} {
	val, err := g.getInputFn(r, g.fields...)
	if err != nil {
		// Set the current `r.err`
		r.err = err
		return err
	}

	// Success!
	return val
}

func (g getInput) execute(r *ExtendedRequest, scope scopeContainer, formatVars *[]interface{}) {
	val := g.retrieve(r, scope)

	// Check if there was an error during `retrieve`
	if r.err != nil {
		return
	}

	// Since this is a `get` operation, it should append to the `formatVars`
	*formatVars = append(*formatVars, val)
}

func (g getInput) SubField(field string) getInput {
	// Add the input `field` to `fields`
	return getInput{
		fields:     append(g.fields, field),
		getInputFn: g.getInputFn,
	}
}

func Get(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (string, error) {
			// Use the default function from the `ExtendedRequest`
			return r.Get_WithErr(args...)
		},
	}
}

func Get_Form(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (string, error) {
			return r.GetFormInput_WithErr(args...)
		},
	}
}

func Get_URL(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (string, error) {
			return r.GetURLInput_WithErr(args...)
		},
	}
}

func GetUserID() getInput {
	return getInput{
		fields: []string{},
		getInputFn: func(r *ExtendedRequest, args ...string) (string, error) {
			// Sanity check the input
			if len(args) != 0 {
				return "", fmt.Errorf("GetUserID should get no arguments")
			}

			// Get the userID and convert it to a `string`
			val, err := r.GetUserID()
			if err != nil {
				return "", err
			}

			// Success!
			return fmt.Sprintf("%d", val), nil
		},
	}
}

// Make sure `getInput` implements `dslInterface`
var _ dslInterface = getInput{}

type setContextVar struct {
	varName string
	ops     []dslInterface
}

func (s setContextVar) retrieve(_ *ExtendedRequest, _ scopeContainer) interface{} {
	// The `retrieve` does nothing
	return nil
}

func (s setContextVar) execute(r *ExtendedRequest, scope scopeContainer, _ *[]interface{}) {
	// Look up the respective `contextGetter` function according to the `varName`
	contextGetter, ok := r.contextGetters[s.varName]

	if !ok {
		// Set the current `r.err`
		r.err = fmt.Errorf("Context type does not have getter function: %s", s.varName)
		return
	}

	// Retrieve and store the values of every operation
	args := make([]interface{}, len(s.ops))
	for i := range args {
		args[i] = s.ops[i].retrieve(r, scope)
	}

	// Perform the context get operation
	val, err := contextGetter(args...)

	if err != nil {
		// Set the current `r.err`
		r.err = err
		return
	}

	// Set the new `val` to the variable `varName` in the lexical `scope`
	scope[s.varName] = val
}

func SetContextVar(name string, ops ...dslInterface) setContextVar {
	return setContextVar{
		varName: name,
		ops:     ops,
	}
}

// Make sure `setContextVar` implements `dslInterface`
var _ dslInterface = setContextVar{}

type getVar struct {
	varName     string
	narrowScope func(*ExtendedRequest, scopeContainer) scopeContainer
}

func (g getVar) retrieve(r *ExtendedRequest, scope scopeContainer) interface{} {
	// Narrow down the `scope` according to the function `narrowScope`
	narrowedScope := g.narrowScope(r, scope)

	// Check if there was an error during `narrowScope`
	if r.err != nil {
		return nil
	}

	// Get the `val` at `varName`
	val, ok := narrowedScope[g.varName]

	if !ok {
		// Set the current `r.err`
		r.err = fmt.Errorf("Variable not found in scope: %s", g.varName)
		return nil
	}

	// Success!
	return val
}

func (g getVar) execute(r *ExtendedRequest, scope scopeContainer, formatVars *[]interface{}) {
	val := g.retrieve(r, scope)

	// Check if there was an error during `retrieve`
	if r.err != nil {
		return
	}

	// Since this is a `get` operation, it should append to the `formatVars`
	*formatVars = append(*formatVars, val)
}

func (g getVar) SubField(field string) getVar {
	return getVar{
		varName: field,
		narrowScope: func(r *ExtendedRequest, scope scopeContainer) scopeContainer {
			// Apply the parent's `narrowScope` first
			scope = g.narrowScope(r, scope)

			// Check if there was an error during `narrowScope`
			if r.err != nil {
				return nil
			}

			// Apply the parent's `varName` to the scope
			scope, ok := scope[g.varName].(scopeContainer)

			if !ok {
				log.Info("LOLOL %v", scope)

				// Set the current `r.err`
				r.err = fmt.Errorf("Variable not found in scope: %s", g.varName)
				return nil
			}

			// Success
			return scope
		},
	}
}

func GetVar(name string) getVar {
	return getVar{
		varName: name,
		narrowScope: func(_ *ExtendedRequest, scope scopeContainer) scopeContainer {
			return scope
		},
	}
}

// TODO:
// Also make sure you are handling errors correctly for custom handler functions

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