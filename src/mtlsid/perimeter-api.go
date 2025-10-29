package mtlsid

// to convert .12 files to .cer + .key file combination
// $ openssl pkcs12 -in client-id.p12 -clcerts -nokeys -out client-id.cer
// $ openssl pkcs12 -in client-id.p12 -clcerts -nodes -nocerts | openssl rsa > client-id.key

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"identity.plus/mtls-gw/global"
)

type Stats struct {
	ValidationCount   int64
	ValidationLatency int64
	TotalLatency      int64
}

var Stats__ = Stats{}

type Client_Validation_Ticket struct {
	Cache     *Identity_Profile
	Added     time.Time
	Serial_No string
	Raw       []byte
}

type Perimeter_API struct {
	Self_Authority     *Self_Authority_API
	Validation_Tickets map[string]Client_Validation_Ticket
	mu                 sync.Mutex
	__client           *http.Client
}

func (idp *Perimeter_API) Cache_Size() int {
	return len(idp.Validation_Tickets)
}

func (idp *Perimeter_API) Purge_Cache() {
	for key := range idp.Validation_Tickets {
		delete(idp.Validation_Tickets, key)
	}
}

func (idp *Perimeter_API) Domain() string {

	files, err := ioutil.ReadDir(idp.Self_Authority.Identity_Dir + "/service-id")
	if err != nil {
		return fmt.Sprintf("error enrolling. identity not issued: %w", err)
	}

	var domain = ""

	// find the service certificate key file
	for _, file := range files {
		// Get the filename
		filename := file.Name()

		// Check if the file ends with ".yam
		if strings.HasSuffix(filename, ".key") {
			domain = strings.TrimSuffix(filename, ".key")
		}
	}

	return domain
}

func (idp *Perimeter_API) Validate_Client_Identity(cert *x509.Certificate, as_service string, cacheable bool) (*Client_Validation_Ticket, string, string, string) {

	validation__, error_cause := idp.Validate_Client_Identity_SN(cert.SerialNumber.String(), as_service, cacheable)

	if error_cause == "" {
		return validation__, cert.Subject.CommonName, cert.Subject.OrganizationalUnit[0], ""
	} else {
		return nil, "", "", error_cause
	}

}

func (idp *Perimeter_API) Validate_Client_Identity_SN(serial_no string, as_service string, cacheable bool) (*Client_Validation_Ticket, string) {

	idp.mu.Lock()

	var cached_validation Client_Validation_Ticket

	// if no elementary errors have been found

	cached_validation = idp.Validation_Tickets[serial_no]
	error_reason := ""

	// if we have a Cache that is not older than 5 minutes, we skip
	if !cacheable || cached_validation.Cache == nil || time.Now().Sub(cached_validation.Added).Seconds() > 60 {
		if global.Config__.Verbose {
			log.Printf("re-validating mTLS ID: %s, from cache (%s)\n", serial_no, cached_validation.Cache == nil)
		}

		start := time.Now()
		bodyBytes, err := idp.identity_inquiry_call(serial_no, as_service)
		//log.Printf("Identity Broker response: %s\n", string(bodyBytes))

		var ans IDP_Response

		if err == nil {
			json.Unmarshal(bodyBytes, &ans)

		} else {
			oc := Simple_Response{Outcome: ("error making validation calls: " + err.Error())}
			ans = IDP_Response{Http_code: 600, SimpleResponse: oc}
		}

		if ans.IdentityProfile.Outcome != "" {

			// in case we receive a profile
			// for this, the certificate needs to be valid, not timed out or reported
			if ans.IdentityProfile.Outcome[0:2] == "OK" {

				if ans.IdentityProfile.OrgID == "" {
					ans.IdentityProfile.OrgID = "- not assigned -"
				}

				// the user has a role in the server
				// let's Cache this result for a few minutes
				// if a Cache exists, we will overwrite it
				cached_validation = Client_Validation_Ticket{
					Cache:     &ans.IdentityProfile,
					Added:     time.Now(),
					Serial_No: serial_no,
					Raw:       bodyBytes,
				}

				if idp.Validation_Tickets == nil {
					// log.Printf("initializting validation cache. ...")
					idp.Validation_Tickets = make(map[string]Client_Validation_Ticket)
				}

				idp.Validation_Tickets[serial_no] = cached_validation

			} else {
				error_reason = string(bodyBytes)
			}

		} else {
			error_reason = string(bodyBytes)
		}

		Stats__.ValidationLatency = time.Since(start).Milliseconds()
		Stats__.TotalLatency += Stats__.ValidationLatency
		Stats__.ValidationCount++
	}

	// we will look a the roles now, and if there are no roles defined
	// the client clearly has no business here
	// we disable this to allow the decision to be taken by whoever calls this method
	//if error_reason == "" && len(cached_validation.Cache.ServiceRoles) == 0 {
	//error_reason = "Certificate is valid no roles on this service"
	//}

	// means it allows the user to continue execution through he proxy
	idp.mu.Unlock()
	return &cached_validation, error_reason
}

func (idp *Perimeter_API) identity_inquiry_call(serial_no string, service string) ([]byte, error) {

	var query = "{\"Identity-Inquiry\":{\"serial-number\": \"" + serial_no + "\""

	if service != "" {
		query += ", \"service\": \"" + service + "\""
	}

	query += "}}"

	return idp.do_get(query)
}

// just a set of wrappers around the methods
func (idp *Perimeter_API) do_get(request_body string) ([]byte, error) {
	return idp.do_call("GET", request_body)
}

/*
func do_put(request_body string) IDP_Response {
	return do_call("PUT", request_body)
}

func do_post(request_body string) IDP_Response {
	return do_call("POST", request_body)
}

func do_delete(request_body string) IDP_Response {
	return do_call("DELETE", request_body)
}
*/
//
// returns 2 values int this order: the http response status (int) and the body of the answer ([]byte)
// - if the http response code is anything but 200, the body should be expected to contain
//   some error description
// - an error of 600 as response code means the call could not be made due to whatever reason
// - 5xx errors mean the request was made, but generated a server error
//
func (idp *Perimeter_API) do_call(method string, request_body string) ([]byte, error) {
	// log.Printf("making https call: %s\n", request_body)

	client, err := idp.client()

	if err != nil {
		log.Printf("error creating client: %s\n", err.Error())
		return nil, err
	}

	// var body_reader io.Reader
	var jsonStr = []byte(request_body)
	client_request, err := http.NewRequest(method, "https://api.identity.plus/v1", bytes.NewBuffer(jsonStr))
	client_request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(client_request)

	defer func() {
		// only close body if it exists to prevent nil reference
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	if err != nil {
		log.Printf("error during https call: %s\n", err.Error())
		return nil, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Printf("error decoding https answer: %s\n", err.Error())
		return nil, err
	}

	return bodyBytes, nil
}

func (idp *Perimeter_API) client() (*http.Client, error) {

	// create the client if not yet created
	if idp.__client == nil {

		if idp.Self_Authority.Identity_Dir == "" || idp.Self_Authority.Device_Name == "" {
			return nil, errors.New("client certificate or key not properly specified. They need to be in separate files as DER Encoded")
		}

		clientCert, err := tls.LoadX509KeyPair(idp.Self_Authority.Identity_Dir+"/"+idp.Self_Authority.Device_Name+".cer", idp.Self_Authority.Identity_Dir+"/"+idp.Self_Authority.Device_Name+".key")

		if err != nil {
			return nil, errors.New("error loading key material: " + err.Error())
		}

		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{clientCert},
		}

		transport := http.Transport{
			TLSClientConfig:     &tlsConfig,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
		}

		idp.__client = &http.Client{
			Transport: &transport,
			Timeout:   time.Second * 5,
		}
	}

	return idp.__client, nil
}
