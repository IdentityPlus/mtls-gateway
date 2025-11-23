package utils

import (
	"encoding/json"
	"net/http"
	"time"
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
