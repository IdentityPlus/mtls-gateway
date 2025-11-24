package utils

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"identity.plus/mtls-gw/global"
)

const LetsEncryptDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

type AcmeDirectory struct {
	Meta struct {
		TermsOfService string `json:"termsOfService"`
	} `json:"meta"`
}

func FetchLets_Encrypt_ToS() string {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(LetsEncryptDirectoryURL)
	if err != nil {
		return "https://letsencrypt.org/"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "https://letsencrypt.org/"
	}

	var directory AcmeDirectory
	if err := json.NewDecoder(resp.Body).Decode(&directory); err != nil {
		return "https://letsencrypt.org/"
	}

	if directory.Meta.TermsOfService == "" {
		return "https://letsencrypt.org/"
	}

	return directory.Meta.TermsOfService
}

func Issue_Lets_Encrypt_cert(domain string, staging bool, force bool, dry_run bool) string {
	// letsencrypt certonly --agree-tos --non-interactive --no-autorenew --register-unsafely-without-email --webroot -w /var/mtls-gateway/letsencrypt/code.identityplus.org -d code.identityplus.org --test-cert
	webroot := global.Config__.DataDirectory + "/letsencrypt/" + domain + "/"
	os.MkdirAll(webroot+"service-id", 0755)

	args := []string{
		"certonly",
		"--agree-tos",
		"--non-interactive",
		"--no-autorenew",
		"--register-unsafely-without-email",
		"--webroot",
		"-w", webroot,
		"-d", domain,
	}

	if dry_run {
		args = append(args, "--dry-run")
	}

	if force {
		args = append(args, "--force-renewal")
	}

	if staging {
		args = append(args, "--test-cert")
	}

	cmd := exec.Command("certbot", args...)

	// Capture stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "Let's Encrypt Certbot failed. More details are available in the logs."
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "Let's Encrypt Certbot failed. More details are available in the logs."
	}

	// Full output buffer (also streamed to log writer)
	var output bytes.Buffer

	// Live copy to logs + capture to buffer
	multiOut := io.MultiWriter(Log_Writer, &output)
	multiErr := io.MultiWriter(Log_Writer, &output)

	go io.Copy(multiOut, stdout)
	go io.Copy(multiErr, stderr)

	// Start the process
	if err := cmd.Start(); err != nil {
		return "Let's Encrypt Certbot failed. More details are available in the logs."
	}

	// Wait for exit
	err = cmd.Wait()

	if err != nil {
		return "Let's Encrypt Certbot failed. More details are available in the logs."
	}

	outStr := output.String()

	if strings.Contains(outStr, "Successfully received certificate") {

		err := CopyFile("/etc/letsencrypt/live/code.identityplus.org/fullchain.pem", global.Config__.DataDirectory+"/letsencrypt/"+domain+"/service-id/"+domain+".cer")
		if err != nil {
			log.Printf("Unable to copy certificate file: %s", err.Error())
			return "Unable to copy certificate files. More details are available in the logs."
		}

		err = CopyFile("/etc/letsencrypt/live/code.identityplus.org/privkey.pem", global.Config__.DataDirectory+"/letsencrypt/"+domain+"/service-id/"+domain+".key")
		if err != nil {
			log.Printf("Unable to copy key file: %s", err.Error())
			return "Unable to copy key files. More details are available in the logs."
		}

		return "renewed"

	} else if strings.Contains(outStr, "Certificate not yet due for renewal") {

		return "Certificate renewal not necessary"

	} else if strings.Contains(outStr, "The dry run was successful") {

		return "success"

	} else {
		return "Let's Encrypt Certbot failed. More details are available in the logs."
	}

}
