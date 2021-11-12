package security

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	errmgmt "github.com/EEAM/gohelplib/errormanagement"
)

type Token struct {
	Key            string
	ExpirationDate time.Time
}

func AquireTokenUrlEncoded(endpointUrl string, queryString url.Values) (string, error) {

	client := &http.Client{}
	req, err := http.NewRequest("POST", endpointUrl, strings.NewReader(queryString.Encode())) // URL-encoded payload
	if err != nil {
		return "", fmt.Errorf("error for creating http.Request for the endpoint: %v and url encoded parameter:\n%v", endpointUrl, queryString.Encode())
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(queryString.Encode())))

	resp, err := client.Do(req)

	if err != nil {
		return "", fmt.Errorf("error for creating http.Request for the endpoint: %v and url encoded parameter:\n%v", endpointUrl, queryString.Encode())
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	bodyS := string(body)
	log.Println(string(body))

	if err != nil && resp.StatusCode == 200 {
		return "", errmgmt.ErrorAccessTokenInvalid{Url: endpointUrl, Code: resp.StatusCode, Message: bodyS}
	}

	return bodyS, nil
}
