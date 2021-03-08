package webauthn_firewall

import (
	"bytes"
	"io/ioutil"
	"net/http"
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

func (wfirewall *WebauthnFirewall) newExtendedRequest(r *http.Request) *ExtendedRequest {
	extendedReq := &ExtendedRequest{
		Request: r,

		// Set the useful helper functions
		GetUserID: func() (int64, error) {
			return wfirewall.getUserID(r)
		},
		getInputDefault: wfirewall.getInputDefault,

		err: nil,
	}

	// Initialize the refill data
	extendedReq.initRefillData()

	return extendedReq
}

func (wfirewall *WebauthnFirewall) wrapHandleFn(
	handleFn func(http.ResponseWriter, *ExtendedRequest)) func(w http.ResponseWriter, r *http.Request) {

	// Wrap the `handleFn` with a function that initializes a `ExtendedRequest`
	wrappedFn := func(w http.ResponseWriter, r *http.Request) {
		extendedReq := wfirewall.newExtendedRequest(r)
		handleFn(w, extendedReq)
	}

	return wrappedFn
}
