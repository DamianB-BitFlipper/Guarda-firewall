package tool

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
)

func PerformHTTP_RequestJSON(req *http.Request, responseBody interface{}) error {
	// TODO: Make this a confiruable option in the `initHTTP` function
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	err = json.NewDecoder(resp.Body).Decode(responseBody)
	if err != nil {
		return err
	}

	// Success!
	return nil
}
