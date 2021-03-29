package webauthn_firewall

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/gorilla/mux"
)

type jsonBody = map[string]interface{}
type getInputFnType func(r *ExtendedRequest, args ...string) (interface{}, error)

func GetFormInput(r *ExtendedRequest, args ...string) (interface{}, error) {
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

func GetURLInput(r *ExtendedRequest, args ...string) (interface{}, error) {
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

func GetJSONInput(r *ExtendedRequest, args ...string) (interface{}, error) {
	// Sanity check the input
	if r == nil {
		err := fmt.Errorf("Nil request received")
		return "", err
	}

	// JSON inputs should at least one argument
	if len(args) < 1 {
		err := fmt.Errorf("JSON inputs expect at least 1 argument. Received: %v", args)
		return "", err
	}

	var body interface{}
	body = make(jsonBody)

	// Unmarshal numbers into the `Number` type
	dec := json.NewDecoder(r.Request.Body)
	dec.UseNumber()

	err := dec.Decode(&body)
	if err != nil {
		return "", err
	}

	// Extract the request value from `body`
	for _, arg := range args {
		cast, ok := body.(jsonBody)
		if !ok {
			err := fmt.Errorf("JSON parse fail. Unable to cast intermediate to jsonBody: %[1]T %[1]v", body)
			return "", err
		}
		body = cast[arg]
	}

	// Refill since future commands may need the request `Body`
	r.Refill()

	// Success!
	return body, nil
}

func castToString(val interface{}) (ret string, err error) {
	switch val.(type) {
	case string:
		ret = val.(string)
	case json.Number:
		ret = val.(json.Number).String()
	default:
		// Record the `err`
		err = fmt.Errorf("JSON parse fail. Unable to cast result to string: %[1]v (%[1]T)", val)
	}

	return ret, err
}

func castToInt64(val interface{}) (ret int64, err error) {
	switch val.(type) {
	case string:
		ret, err = strconv.ParseInt(val.(string), 10, 64)
	case json.Number:
		ret, err = val.(json.Number).Int64()
	default:
		// Record the `err`
		err = fmt.Errorf("JSON parse fail. Unable to cast result to int64: %[1]v (%[1]T)", val)
	}

	return ret, err
}

func castToArray(val interface{}) (ret []interface{}, err error) {
	switch val.(type) {
	case []interface{}:
		ret = val.([]interface{})
	default:
		// Record the `err`
		err = fmt.Errorf("JSON parse fail. Unable to cast result to []interface{}: %[1]v (%[1]T)", val)
	}

	return ret, err
}

func (r *ExtendedRequest) getInput_WithErr_Helper(getInputFn getInputFnType, args ...string) (interface{}, error) {
	// If an error has already occured, pass it onward
	if r.err != nil {
		return nil, r.err
	}

	val, err := getInputFn(r, args...)

	// If the `err != nil`, record the error and return
	if err != nil {
		r.err = err
		return nil, err
	}

	// Success!
	return val, err
}

func (r *ExtendedRequest) getInputString_WithErr_Helper(getInputFn getInputFnType, args ...string) (string, error) {
	val, err := r.getInput_WithErr_Helper(getInputFn, args...)
	if err != nil {
		// The `r.err` was set by the helper function
		return "", err
	}

	// Convert the `val` to a `string`
	ret, err := castToString(val)
	if err != nil {
		// Record the error and return
		r.err = err
		return "", err
	}

	// Success!
	return ret, err
}

func (r *ExtendedRequest) getInputInt64_WithErr_Helper(getInputFn getInputFnType, args ...string) (int64, error) {
	val, err := r.getInput_WithErr_Helper(getInputFn, args...)
	if err != nil {
		// The `r.err` was set by the helper function
		return 0, err
	}

	// Convert the `val` to an `int64`
	ret, err := castToInt64(val)
	if err != nil {
		// Record the error and return
		r.err = err
		return 0, err
	}

	// Success!
	return ret, err
}

func (r *ExtendedRequest) getInputArray_WithErr_Helper(getInputFn getInputFnType, args ...string) ([]interface{}, error) {
	val, err := r.getInput_WithErr_Helper(getInputFn, args...)
	if err != nil {
		// The `r.err` was set by the helper function
		return []interface{}{}, err
	}

	// Convert the `val` to an `[]interface{}`
	ret, err := castToArray(val)
	if err != nil {
		// Record the error and return
		r.err = err
		return []interface{}{}, err
	}

	// Success!
	return ret, err
}

//
// Form value Get functions
//

func (r *ExtendedRequest) GetFormInput_WithErr(args ...string) (string, error) {
	return r.getInputString_WithErr_Helper(GetFormInput, args...)
}

func (r *ExtendedRequest) GetFormInput(args ...string) string {
	val, _ := r.getInputString_WithErr_Helper(GetFormInput, args...)
	return val
}

func (r *ExtendedRequest) GetFormInputInt64_WithErr(args ...string) (int64, error) {
	return r.getInputInt64_WithErr_Helper(GetFormInput, args...)
}

func (r *ExtendedRequest) GetFormInputInt64(args ...string) int64 {
	val, _ := r.getInputInt64_WithErr_Helper(GetFormInput, args...)
	return val
}

func (r *ExtendedRequest) GetFormInputArray_WithErr(args ...string) ([]interface{}, error) {
	return r.getInputArray_WithErr_Helper(GetFormInput, args...)
}

func (r *ExtendedRequest) GetFormInputArray(args ...string) []interface{} {
	val, _ := r.getInputArray_WithErr_Helper(GetFormInput, args...)
	return val
}

//
// URL value Get functions
//

func (r *ExtendedRequest) GetURLInput_WithErr(args ...string) (string, error) {
	return r.getInputString_WithErr_Helper(GetURLInput, args...)
}

func (r *ExtendedRequest) GetURLInput(args ...string) string {
	val, _ := r.getInputString_WithErr_Helper(GetURLInput, args...)
	return val
}

func (r *ExtendedRequest) GetURLInputInt64_WithErr(args ...string) (int64, error) {
	return r.getInputInt64_WithErr_Helper(GetURLInput, args...)
}

func (r *ExtendedRequest) GetURLInputInt64(args ...string) int64 {
	val, _ := r.getInputInt64_WithErr_Helper(GetURLInput, args...)
	return val
}

func (r *ExtendedRequest) GetURLInputArray_WithErr(args ...string) ([]interface{}, error) {
	return r.getInputArray_WithErr_Helper(GetURLInput, args...)
}

func (r *ExtendedRequest) GetURLInputArray(args ...string) []interface{} {
	val, _ := r.getInputArray_WithErr_Helper(GetURLInput, args...)
	return val
}

//
// JSON Get functions
//

func (r *ExtendedRequest) GetJSONInput_WithErr(args ...string) (string, error) {
	return r.getInputString_WithErr_Helper(GetJSONInput, args...)
}

func (r *ExtendedRequest) GetJSONInput(args ...string) string {
	val, _ := r.getInputString_WithErr_Helper(GetJSONInput, args...)
	return val
}

func (r *ExtendedRequest) GetJSONInputInt64_WithErr(args ...string) (int64, error) {
	return r.getInputInt64_WithErr_Helper(GetJSONInput, args...)
}

func (r *ExtendedRequest) GetJSONInputInt64(args ...string) int64 {
	val, _ := r.getInputInt64_WithErr_Helper(GetJSONInput, args...)
	return val
}

func (r *ExtendedRequest) GetJSONInputArray_WithErr(args ...string) ([]interface{}, error) {
	return r.getInputArray_WithErr_Helper(GetJSONInput, args...)
}

func (r *ExtendedRequest) GetJSONInputArray(args ...string) []interface{} {
	val, _ := r.getInputArray_WithErr_Helper(GetJSONInput, args...)
	return val
}

//
// The default Get functions
//

func (r *ExtendedRequest) Get_WithErr(args ...string) (string, error) {
	return r.getInputString_WithErr_Helper(r.getInputDefault, args...)
}

func (r *ExtendedRequest) Get(args ...string) string {
	val, _ := r.getInputString_WithErr_Helper(r.getInputDefault, args...)
	return val
}

func (r *ExtendedRequest) GetInt64_WithErr(args ...string) (int64, error) {
	return r.getInputInt64_WithErr_Helper(r.getInputDefault, args...)
}

func (r *ExtendedRequest) GetInt64(args ...string) int64 {
	val, _ := r.getInputInt64_WithErr_Helper(r.getInputDefault, args...)
	return val
}

func (r *ExtendedRequest) GetArray_WithErr(args ...string) ([]interface{}, error) {
	return r.getInputArray_WithErr_Helper(r.getInputDefault, args...)
}

func (r *ExtendedRequest) GetArray(args ...string) []interface{} {
	val, _ := r.getInputArray_WithErr_Helper(r.getInputDefault, args...)
	return val
}

//
// The context Get functions
//

func (r *ExtendedRequest) GetContext(contextName string, args ...interface{}) interface{} {
	val, _ := r.GetContext_WithErr(contextName, args...)
	return val
}

func (r *ExtendedRequest) GetContext_WithErr(contextName string, args ...interface{}) (interface{}, error) {
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
