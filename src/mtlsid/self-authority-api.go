package mtlsid

// to convert .12 files to .cer + .key file combination
// $ openssl pkcs12 -in client-id.p12 -clcerts -nokeys -out client-id.cer
// $ openssl pkcs12 -in client-id.p12 -clcerts -nodes -nocerts | openssl rsa > client-id.key

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Self_Authority_API struct {
	TrustStore   []string `yaml:"trust_store"`
	Verbose      bool     `yaml:"verbose"`
	Service      string   `yaml:"identity_broker"`
	Identity_Dir string   `yaml:"id_directory"`
	Device_Name  string   `yaml:"device_name"`

	client_certificate *tls.Certificate
}

func (cli *Self_Authority_API) Invalidate() {
	cli.client_certificate = nil
}

func (cli *Self_Authority_API) insecure_call(endpoint string, method string, request_body string) (string, []byte) {
	client, err := cli.client(nil)

	if err != nil {
		return "Unable to create http client: " + err.Error(), nil
	}

	return cli.do_call(client, endpoint, method, request_body)
}

func (cli *Self_Authority_API) Client_Certificate() (*tls.Certificate, error) {
	if cli.client_certificate == nil {
		client_certificate, err := tls.LoadX509KeyPair(cli.Identity_Dir+"/"+cli.Device_Name+".cer", cli.Identity_Dir+"/"+cli.Device_Name+".key")
		if err != nil {
			return nil, fmt.Errorf("error loading key material: %v", err.Error())
		}

		cli.client_certificate = &client_certificate
	}

	return cli.client_certificate, nil
}

func (cli *Self_Authority_API) secure_call(endpoint string, method string, request_body string) (string, []byte) {

	client_certificate, err := cli.Client_Certificate()
	if err != nil {
		return "error loading key material: " + err.Error(), nil
	}

	client, err := cli.client(client_certificate)

	if err != nil {
		return "Unable to create http client: " + err.Error(), nil
	}

	return cli.do_call(client, endpoint, method, request_body)
}

func (cli *Self_Authority_API) do_call(client *http.Client, endpoint string, method string, request_body string) (string, []byte) {
	if cli.Verbose {
		fmt.Println(request_body)
	}

	// var body_reader io.Reader
	var jsonStr = []byte(request_body)
	client_request, err := http.NewRequest(method, endpoint, bytes.NewBuffer(jsonStr))
	client_request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(client_request)

	defer func() {
		// only close body if it exists to prevent nil reference
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	if err != nil {
		return "error during https call: " + err.Error(), nil
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "error decoding https answer: " + err.Error(), nil
	}

	return "", bodyBytes
}

func (cli *Self_Authority_API) client(client_certificate *tls.Certificate) (*http.Client, error) {

	trusted_authorities, err := x509.SystemCertPool()

	if err != nil && cli.Verbose {
		fmt.Printf("Unable to load system trust store: %v\n", err)
	}

	if trusted_authorities == nil {
		trusted_authorities = x509.NewCertPool()
	}

	for _, ca := range cli.TrustStore {
		root_cert, err := ioutil.ReadFile(ca)

		if err != nil {
			fmt.Printf("Unable to load trust material %s: %v\n", ca, err)
		}

		_ = trusted_authorities.AppendCertsFromPEM(root_cert)
	}

	var client_certificates []tls.Certificate
	if client_certificate != nil {
		client_certificates = []tls.Certificate{*client_certificate}
	}

	tlsConfig := tls.Config{
		Certificates: client_certificates,
		RootCAs:      trusted_authorities,
	}

	transport := http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	__client := &http.Client{
		Transport: &transport,
		Timeout:   time.Second * 40,
	}

	return __client, nil
}

func (cli *Self_Authority_API) Interactive_enroll_user_agent() string {
	err, ans := cli.insecure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"request_oob_unlock\", \"args\": {\"no-redundancy\":false}}")

	if err != "" {
		return "Failed requesting login intent: " + err
	}

	if cli.Verbose {
		// fmt.Printf(string(ans))
	}

	var response Intent_Response
	json.Unmarshal(ans, &response)

	qr_code := strings.Split(response.Result.QR, ";")
	fmt.Println("")
	fmt.Println("")
	fmt.Print("      ")
	for i := 0; i < len(qr_code); i += 2 {
		for j := 0; j < len(qr_code[i]); j++ {

			if qr_code[i][j] == '1' && (i > len(qr_code)-3 || qr_code[i+1][j] == '0') {
				fmt.Printf("\u2580") // upper half block
			} else if qr_code[i][j] == '1' && i < len(qr_code)-2 && qr_code[i+1][j] == '1' {
				fmt.Printf("\u2588") // full block
			} else if qr_code[i][j] == '0' && i < len(qr_code)-2 && qr_code[i+1][j] == '1' {
				fmt.Printf("\u2584") // lower half block
			} else {
				fmt.Printf(" ")
			}
		}

		fmt.Println("")
		fmt.Print("      ")
	}
	fmt.Println("")
	fmt.Println("")
	fmt.Println("Please scan the above QR Code with your Identity Plus App.")
	fmt.Print("Waiting ...")

	for i := 0; i < 10; i++ {
		err, ans = cli.insecure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"oob_unlock\", \"args\": {\"token\": \""+response.Result.Token+"\", \"intent\": \""+response.Result.Intent+"\", \"keep-alive\":10}}}")

		if err != "" {
			return string(err)
		}

		var response Auth_Response
		json.Unmarshal(ans, &response)

		if (response.Error != "" || response.Result.Outcome != "logged in") && cli.Verbose {
			fmt.Println(response.Error + ", trying again")
		} else {
			fmt.Printf(".")
		}

		if response.Result.Outcome == "logged in" {
			return "\n" + cli.do_enroll(response.Result.Token) + "\n"
		}

	}

	return "Login timed out"
}

func (cli *Self_Authority_API) do_enroll(token string) string {
	err, ans := cli.insecure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"issue_certificate\", \"args\": {\"token\": \""+token+"\", \"device\": \""+cli.Device_Name+"\", \"protect\":true}}")

	if err != "" {
		return "Failed issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	if cli.Verbose {
		fmt.Printf("writing certificate information into: " + cli.Identity_Dir + "/")
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".p12", p12_cert, 0644)
	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".password", []byte(agent_identity.Result.Password), 0644)

	pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".cer", pem_cert, 0644)

	pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".key", pem_key, 0644)

	return "success"
}

func (cli *Self_Authority_API) Enroll_user_agent(authorization string) string {
	err, ans := cli.insecure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"qrc_unlock\", \"args\": {\"code\": \""+authorization+"\"}}")

	if err != "" {
		return "Login failed: " + err
	}

	if cli.Verbose {
		// fmt.Printf(string(ans))
	}

	var response Auth_Response
	json.Unmarshal(ans, &response)

	if response.Error != "" {
		return "Login failed: " + response.Error
	}

	if response.Result.Outcome != "logged in" {
		return "Login failed: " + response.Result.Outcome
	}

	return cli.do_enroll(response.Result.Token)
}

func (cli *Self_Authority_API) Employ_service_agent(authorization string) string {

	err, ans := cli.insecure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"issue_service_agent_identity\", \"args\": {\"authorization\": \""+authorization+"\", \"agent-name\": \""+cli.Device_Name+"\", \"protect\":true}}")

	if err != "" {
		return "Failed issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	if cli.Verbose {
		// fmt.Printf(string(ans))
	}

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	path := cli.Identity_Dir
	if os.MkdirAll(path, os.ModePerm) != nil {
		log.Println(err)
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".p12", p12_cert, 0644)
	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".password", []byte(agent_identity.Result.Password), 0644)

	pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".cer", pem_cert, 0644)

	pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".key", pem_key, 0644)

	return "success"
}

func (cli *Self_Authority_API) Assist_enroll(managed_service string) string {
	err, ans := cli.secure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"assist\", \"args\": {\"managed-service\": \""+managed_service+"\"}}")

	if err != "" {
		return "Failed generating autoprovisioning token: " + err
	}

	var response Autoprovisioning_Token_Response
	json.Unmarshal(ans, &response)

	if response.Error != "" {
		return "Failed generating autoprovisioning token: " + response.Error
	}

	return response.Result.Token
}

func (cli *Self_Authority_API) Enroll_unified(authorization string) string {

	err, ans := cli.insecure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"enroll\", \"args\": {\"authorization\": \""+authorization+"\", \"agent-name\": \""+cli.Device_Name+"\", \"protect\":true}}")

	if err != "" {
		return "Failed issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	if cli.Verbose {
		// fmt.Printf(string(ans))
	}

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	path := cli.Identity_Dir
	if os.MkdirAll(path, os.ModePerm) != nil {
		log.Println(err)
	}

	if cli.Verbose {
		fmt.Printf("writing certificate information into: " + cli.Identity_Dir + "/...")
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".p12", p12_cert, 0644)
	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".password", []byte(agent_identity.Result.Password), 0644)

	pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".cer", pem_cert, 0644)

	pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
	if derr != nil {
		return "Failed decoding certificate: " + err
	}

	ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".key", pem_key, 0644)

	return "success"
}

func (cli *Self_Authority_API) Renew(tentative bool) string {

	err, ans := cli.secure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"renew_certificate\", \"args\": {\"device\": \""+cli.Device_Name+"\", \"protect\":true, \"tentative\":"+strconv.FormatBool(tentative)+"}}")

	if err != "" {
		return "Failed issuing certificate: " + err
	}

	var agent_identity X509_Identity_Response
	json.Unmarshal(ans, &agent_identity)

	if agent_identity.Error != "" {
		return "Failed issuing certificate: " + agent_identity.Error
	}

	if agent_identity.Result.Outcome == "renewed" {

		p12_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.P12)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".p12", p12_cert, 0644)
		ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".password", []byte(agent_identity.Result.Password), 0644)

		pem_cert, derr := base64.StdEncoding.DecodeString(agent_identity.Result.Certificate)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".cer", pem_cert, 0644)

		pem_key, derr := base64.StdEncoding.DecodeString(agent_identity.Result.PrivateKey)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		ioutil.WriteFile(cli.Identity_Dir+"/"+cli.Device_Name+".key", pem_key, 0644)

		cli.Invalidate()
	}

	return agent_identity.Result.Outcome
}

func (cli *Self_Authority_API) Issue_service_identity(force bool) string {
	err, ans := cli.secure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"issue_service_certificate\", \"args\": {\"force-renew\":"+strconv.FormatBool(force)+"}}")

	if cli.Verbose {
		fmt.Printf(string(ans))
	}

	if err != "" {
		return "Failed issuing certificate: " + err
	}

	var service_identity X509_Identity_Response
	json.Unmarshal(ans, &service_identity)

	if service_identity.Error != "" {
		return "Failed issuing certificate: " + service_identity.Error
	}

	if service_identity.Result.Outcome == "renewed" {

		p12_cert, derr := base64.StdEncoding.DecodeString(service_identity.Result.P12)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		path := cli.Identity_Dir + "/service-id/"
		if os.MkdirAll(path, os.ModePerm) != nil {
			log.Println(err)
		}

		ioutil.WriteFile(cli.Identity_Dir+"/service-id/"+service_identity.Result.Name+".p12", p12_cert, 0644)
		ioutil.WriteFile(cli.Identity_Dir+"/service-id/"+service_identity.Result.Name+".password", []byte(service_identity.Result.Password), 0644)

		pem_cert, derr := base64.StdEncoding.DecodeString(service_identity.Result.Certificate)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		ioutil.WriteFile(cli.Identity_Dir+"/service-id/"+service_identity.Result.Name+".cer", pem_cert, 0644)

		pem_key, derr := base64.StdEncoding.DecodeString(service_identity.Result.PrivateKey)
		if derr != nil {
			return "Failed decoding certificate: " + err
		}

		ioutil.WriteFile(cli.Identity_Dir+"/service-id/"+service_identity.Result.Name+".key", pem_key, 0644)
	}

	return service_identity.Result.Outcome
}

func (cli *Self_Authority_API) Get_trust_chain() string {
	err, ans := cli.secure_call("https://platform."+cli.Service+"/download/trust-chain?format=pem", "GET", "")

	if err != "" {
		return "unable to download trust chain: " + err
	}

	path := cli.Identity_Dir + "/service-id/"
	if os.MkdirAll(path, os.ModePerm) != nil {
		log.Println(err)
	}

	ioutil.WriteFile(cli.Identity_Dir+"/service-id/identity-plus-root-ca.cer", ans, 0644)

	return "trust chain saved: " + cli.Identity_Dir + "/service-id/identity-plus-root-ca.cer"
}

func (cli *Self_Authority_API) List_devices() string {
	err, ans := cli.secure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"get_active_identities\", \"args\": {}}")

	if err != "" {
		return "Failed to list active mTLS IDs for agent: " + err
	}

	// var agent_identity X509_Identity_Response
	// json.Unmarshal(ans, &agent_identity)

	return string(ans)
}

func (cli *Self_Authority_API) List_service_roles() string {
	err, ans := cli.secure_call("https://signon."+cli.Service+"/api/v1", "POST", "{\"operation\": \"get_service_roles\", \"args\": {}}")

	if err != "" {
		return "Failed to get service roles: " + err
	}

	// var agent_identity X509_Identity_Response
	// json.Unmarshal(ans, &agent_identity)

	return string(ans)
}

func (cli *Self_Authority_API) Call(url string) string {
	err, ans := cli.secure_call(url, "GET", "")

	if err != "" {
		return "Error Geting URL: " + err
	}

	return string(ans)
}
