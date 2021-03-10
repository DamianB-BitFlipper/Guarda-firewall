package webauthn_firewall

import (
	"fmt"
	"strconv"

	"github.com/gorilla/mux"
)

func GetFormInput(r *ExtendedRequest, args ...string) (string, error) {
	// Sanity check the input
	if r == nil {
		err := fmt.Errorf("Nil request received")
		return "", err
	}

	// Form fields should only have a single argument
	if len(args) != 1 {
		err := fmt.Errorf("Form inputs expect only 1 argument. Received: %v", args)
		return "", err
	}

	// Retrieve the respective form value
	val := r.Request.FormValue(args[0])
	if val == "" {
		err := fmt.Errorf("Invalid form-data parameters")
		return "", err
	}

	// Success!
	return val, nil
}

func GetURLInput(r *ExtendedRequest, args ...string) (string, error) {
	// Sanity check the input
	if r == nil {
		err := fmt.Errorf("Nil request received")
		return "", err
	}

	// URL inputs should only have a single argument
	if len(args) != 1 {
		err := fmt.Errorf("URL inputs expect only 1 argument. Received: %v", args)
		return "", err
	}

	// Get the URL input for `args[0]`
	val := mux.Vars(r.Request)[args[0]]

	// Success!
	return val, nil
}

func (r *ExtendedRequest) getInput_WithErr_Helper(getInputFn getInputFnType, args ...string) (string, error) {
	// If an error has already occured, pass it onward
	if r.err != nil {
		return "", r.err
	}

	val, err := getInputFn(r, args...)

	// If the `err != nil`, record the error and return
	if err != nil {
		r.err = err
		return "", err
	}

	// Success!
	return val, err
}

func (r *ExtendedRequest) getInputInt64_WithErr_Helper(getInputFn getInputFnType, args ...string) (int64, error) {
	val, err := r.getInput_WithErr_Helper(getInputFn, args...)
	if err != nil {
		// The `r.err` was set by the helper function
		return 0, err
	}

	valInt, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		// Set the current error `r.err`
		r.err = err
		return 0, err
	}

	// Success!
	return valInt, err
}

//
// Form value Get functions
//

func (r *ExtendedRequest) GetFormInput_WithErr(args ...string) (string, error) {
	return r.getInput_WithErr_Helper(GetFormInput, args...)
}

func (r *ExtendedRequest) GetFormInput(args ...string) string {
	val, _ := r.getInput_WithErr_Helper(GetFormInput, args...)
	return val
}

func (r *ExtendedRequest) GetFormInputInt64_WithErr(args ...string) (int64, error) {
	return r.getInputInt64_WithErr_Helper(GetFormInput, args...)
}

func (r *ExtendedRequest) GetFormInputInt64(args ...string) int64 {
	val, _ := r.getInputInt64_WithErr_Helper(GetFormInput, args...)
	return val
}

//
// URL value Get functions
//

func (r *ExtendedRequest) GetURLInput_WithErr(args ...string) (string, error) {
	return r.getInput_WithErr_Helper(GetURLInput, args...)
}

func (r *ExtendedRequest) GetURLInput(args ...string) string {
	val, _ := r.getInput_WithErr_Helper(GetURLInput, args...)
	return val
}

func (r *ExtendedRequest) GetURLInputInt64_WithErr(args ...string) (int64, error) {
	return r.getInputInt64_WithErr_Helper(GetURLInput, args...)
}

func (r *ExtendedRequest) GetURLInputInt64(args ...string) int64 {
	val, _ := r.getInputInt64_WithErr_Helper(GetURLInput, args...)
	return val
}

//
// The default Get functions
//

func (r *ExtendedRequest) Get_WithErr(args ...string) (string, error) {
	return r.getInput_WithErr_Helper(r.getInputDefault, args...)
}

func (r *ExtendedRequest) Get(args ...string) string {
	val, _ := r.getInput_WithErr_Helper(r.getInputDefault, args...)
	return val
}

func (r *ExtendedRequest) GetInt64_WithErr(args ...string) (int64, error) {
	return r.getInputInt64_WithErr_Helper(r.getInputDefault, args...)
}

func (r *ExtendedRequest) GetInt64(args ...string) int64 {
	val, _ := r.getInputInt64_WithErr_Helper(r.getInputDefault, args...)
	return val
}

//
// The context Get functions
//

func (r *ExtendedRequest) GetContext(contextName string, args ...interface{}) (interface{}, error) {
	// Look up the respective `contextGetter` function according to the `contextName`
	contextGetter, ok := r.contextGetters[contextName]

	if !ok {
		// Set the current `r.err`
		r.err = fmt.Errorf("Context type does not have getter function: %s", contextName)
		return nil, r.err
	}

	// Perform the context get operation
	val, err := contextGetter(args...)
	if err != nil {
		// Set the current `r.err`
		r.err = err
		return nil, r.err
	}

	// Success!
	return val, nil
}
