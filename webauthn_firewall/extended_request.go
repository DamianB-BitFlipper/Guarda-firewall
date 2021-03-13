package webauthn_firewall

import (
	"bytes"
	"io/ioutil"
	"net/http"

	log "unknwon.dev/clog/v2"
)

type RequestRefiller struct {
	request *http.Request
	data    []byte
}

type ExtendedRequest struct {
	*http.Request
	data []byte

	GetUserID       func() (int64, error)
	getInputDefault getInputFnType
	contextGetters  ContextGettersType

	err error
}

func (er *ExtendedRequest) initRefillData() {
	// Get the `data` from the `http.Request` so that it can be restored again if necessary
	data, err := ioutil.ReadAll(er.Request.Body)
	if err != nil {
		// Set the current `er.err`
		er.err = err
		return
	}

	// Set `data` field
	er.data = data

	// Refill the `http.Request` since it was read during setup
	er.Refill()
}

func (er *ExtendedRequest) Refill() {
	// Reload the `r.Body` from the `data` before reading the form fields
	er.Request.Body = ioutil.NopCloser(bytes.NewReader(er.data))
}

func (er *ExtendedRequest) IgnoreError(getter func(...string) string, args ...string) string {
	// If there already has been an error, retain it
	if er.err != nil {
		return ""
	}

	ret := getter(args...)
	// If there was an error during `getter` execution, clear it
	if er.err != nil {
		er.err = nil
	}

	return ret
}

func (er *ExtendedRequest) IgnoreError_WithErr(getter func(...string) (string, error), args ...string) (string, error) {
	// If there already has been an error, retain it
	if er.err != nil {
		return "", er.err
	}

	ret, err := getter(args...)
	// If there was an error during `getter` execution, clear it
	if er.err != nil {
		er.err = nil
	}

	// Still be sure to return the `err`
	return ret, err
}

func (er *ExtendedRequest) AnyErrors(w http.ResponseWriter) bool {
	if er.err != nil {
		log.Error("%v", er.err)
		http.Error(w, er.err.Error(), http.StatusInternalServerError)
		return true
	}

	// No errors!
	return false
}

func (wfirewall *WebauthnFirewall) newExtendedRequest(r *http.Request) *ExtendedRequest {
	extendedReq := &ExtendedRequest{
		Request: r,

		// Set the useful helper functions
		GetUserID: func() (int64, error) {
			return wfirewall.getUserID(r)
		},
		getInputDefault: wfirewall.getInputDefault,
		contextGetters:  wfirewall.contextGetters,

		err: nil,
	}

	// Initialize the refill data
	extendedReq.initRefillData()

	return extendedReq
}

func (wfirewall *WebauthnFirewall) wrapHandleFn(handleFn HandlerFnType) func(w http.ResponseWriter, r *http.Request) {
	// Wrap the `handleFn` with a function that initializes a `ExtendedRequest`
	wrappedFn := func(w http.ResponseWriter, r *http.Request) {
		extendedReq := wfirewall.newExtendedRequest(r)
		handleFn(w, extendedReq)
	}

	return wrappedFn
}
