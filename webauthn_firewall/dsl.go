package webauthn_firewall

import (
	"fmt"

	log "unknwon.dev/clog/v2"
)

// The `scopeContainer` is an alias rather than a new type because this type has to
// be the same as generic JSON parses which are `map[string]interface{}`
type scopeContainer = map[string]interface{}
type StructContext = scopeContainer

type dslInterface interface {
	// Retrieves the result of an operation
	retrieve(r *ExtendedRequest, scope scopeContainer) interface{}

	// Applies the operation to the `scope` and `formatVars`
	execute(r *ExtendedRequest, scope scopeContainer, formatVars *[]interface{})
}

type getInput struct {
	fields     []string
	getInputFn func(*ExtendedRequest, ...string) (interface{}, error)
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
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			// Use the default function from the `ExtendedRequest`
			return r.Get_WithErr(args...)
		},
	}
}

func GetInt64(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			// Use the default function from the `ExtendedRequest`
			return r.GetInt64_WithErr(args...)
		},
	}
}

func GetArray(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			// Use the default function from the `ExtendedRequest`
			return r.GetArray_WithErr(args...)
		},
	}
}

func Get_Form(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetFormInput_WithErr(args...)
		},
	}
}

func GetInt64_Form(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetFormInputInt64_WithErr(args...)
		},
	}
}

func GetArray_Form(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetFormInputArray_WithErr(args...)
		},
	}
}

func Get_URL(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetURLInput_WithErr(args...)
		},
	}
}

func GetInt64_URL(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetURLInputInt64_WithErr(args...)
		},
	}
}

func GetArray_URL(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetURLInputArray_WithErr(args...)
		},
	}
}

func Get_JSON(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetJSONInput_WithErr(args...)
		},
	}
}

func GetInt64_JSON(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetJSONInputInt64_WithErr(args...)
		},
	}
}

func GetArray_JSON(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetJSONInputArray_WithErr(args...)
		},
	}
}

func Get_URLParam(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetURLParam_WithErr(args...)
		},
	}
}

func GetInt64_URLParam(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetURLParamInt64_WithErr(args...)
		},
	}
}

func GetArray_URLParam(field string) getInput {
	return getInput{
		fields: []string{field},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			return r.GetURLParamArray_WithErr(args...)
		},
	}
}

func GetUserID() getInput {
	return getInput{
		fields: []string{},
		getInputFn: func(r *ExtendedRequest, args ...string) (interface{}, error) {
			// Sanity check the input
			if len(args) != 0 {
				return 0, fmt.Errorf("GetUserID should get no arguments")
			}

			// Get the userID and convert it to a `string`
			val, err := r.GetUserID()
			if err != nil {
				return 0, err
			}

			// Success!
			return val, nil
		},
	}
}

// Make sure `getInput` implements `dslInterface`
var _ dslInterface = getInput{}

type getContext struct {
	contextName string
	subFields   []string
	ops         []dslInterface
}

func (g getContext) retrieve(r *ExtendedRequest, scope scopeContainer) interface{} {
	// Retrieve and store the values of every operation
	args := make([]interface{}, len(g.ops))
	for i := range args {
		args[i] = g.ops[i].retrieve(r, scope)
	}

	// Perform the context get operation
	val, err := r.GetContext_WithErr(g.contextName, args...)
	if err != nil {
		return err
	}

	// TODO: This should error check that `subField` is actually a sub field
	for _, subField := range g.subFields {
		val = val.(StructContext)[subField]
	}

	// Success!
	return val
}

func (g getContext) execute(r *ExtendedRequest, scope scopeContainer, formatVars *[]interface{}) {
	val := g.retrieve(r, scope)

	// Check if there was an error during `retrieve`
	if r.err != nil {
		return
	}

	// Since this is a `get` operation, it should append to the `formatVars`
	*formatVars = append(*formatVars, val)
}

func (g getContext) SubField(field string) getContext {
	return getContext{
		contextName: g.contextName,
		subFields:   append(g.subFields, field),
		ops:         g.ops,
	}
}

func GetContext(name string, ops ...dslInterface) getContext {
	return getContext{
		contextName: name,
		subFields:   []string{},
		ops:         ops,
	}
}

// Make sure `getContext` implements `dslInterface`
var _ dslInterface = getContext{}

type getVar struct {
	varName     string
	narrowScope func(*ExtendedRequest, scopeContainer) scopeContainer
}

func (g getVar) retrieve(r *ExtendedRequest, scope scopeContainer) interface{} {
	// Narrow down the `scope` according to the function `narrowScope`
	narrowedScope := g.narrowScope(r, scope)

	// Check if there was an error during `narrowScope`
	if r.err != nil {
		return r.err
	}

	// Get the `val` at `varName`
	val, ok := narrowedScope[g.varName]

	if !ok {
		// Set the current `r.err`
		r.err = fmt.Errorf("Variable not found in scope: %s", g.varName)
		return r.err
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

type setVar struct {
	varName string
	valOp   dslInterface
}

func (s setVar) retrieve(_ *ExtendedRequest, _ scopeContainer) interface{} {
	// The `retrieve` does nothing
	return nil
}

func (s setVar) execute(r *ExtendedRequest, scope scopeContainer, _ *[]interface{}) {
	// Extract the `val` of `s.valOp`
	val := s.valOp.retrieve(r, scope)

	// Check if there was an error during `retrieve`
	if r.err != nil {
		return
	}

	// Set the new `scope` variable
	scope[s.varName] = val
}

func SetVar(name string, val dslInterface) setVar {
	return setVar{
		varName: name,
		valOp:   val,
	}
}

func SetContextVar(name string, ops ...dslInterface) setVar {
	return setVar{
		varName: name,
		valOp:   GetContext(name, ops...),
	}
}

// Make sure `setVar` implements `dslInterface`
var _ dslInterface = setVar{}

type logOp struct {
	format string
	ops    []dslInterface
}

func (l logOp) retrieve(_ *ExtendedRequest, _ scopeContainer) interface{} {
	// The `retrieve` does nothing
	return nil
}

func (l logOp) execute(r *ExtendedRequest, scope scopeContainer, _ *[]interface{}) {
	// Retrieve and save the values of every operation
	args := make([]interface{}, len(l.ops))
	for i := range args {
		args[i] = l.ops[i].retrieve(r, scope)
	}

	log.Info(l.format, args...)
}

func Log(format string, ops ...dslInterface) logOp {
	return logOp{
		format: format,
		ops:    ops,
	}
}

// Make sure `logOp` implements `dslInterface`
var _ dslInterface = logOp{}

type applyOp struct {
	fn  func(...interface{}) (interface{}, error)
	ops []dslInterface
}

func (a applyOp) retrieve(r *ExtendedRequest, scope scopeContainer) interface{} {
	// Retrieve and save the values of every operation
	args := make([]interface{}, len(a.ops))
	for i := range args {
		args[i] = a.ops[i].retrieve(r, scope)
	}

	ret, err := a.fn(args...)
	if err != nil {
		// Set the current `r.err`
		r.err = err
		return err
	}

	return ret
}

func (a applyOp) execute(r *ExtendedRequest, scope scopeContainer, formatVars *[]interface{}) {
	val := a.retrieve(r, scope)

	// Check if there was an error during `retrieve`
	if r.err != nil {
		return
	}

	// Since this is a `get` operation, it should append to the `formatVars`
	*formatVars = append(*formatVars, val)
}

func Apply(fn func(...interface{}) (interface{}, error), ops ...dslInterface) applyOp {
	return applyOp{
		fn:  fn,
		ops: ops,
	}
}

// Make sure `applyOp` implements `dslInterface`
var _ dslInterface = applyOp{}

func (wfirewall *WebauthnFirewall) Authn(formatString string, ops ...dslInterface) HandlerFnType {
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
