package tool

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
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

	// Some sort of an error occurred at the server-side
	if resp.StatusCode != http.StatusOK {
		// The error text is inside of the `resp.Body`
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("%s", body)
	}

	err = json.NewDecoder(resp.Body).Decode(responseBody)
	if err != nil {
		return err
	}

	// Success!
	return nil
}
