package handlers

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"

	"identity.plus/mtls-gw/global"
)

func List_Service_Configurations() ([]string, error) {
	// Directory containing the files
	dir := global.Config__.DataDirectory + "/identity"

	// Read all files in the directory
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("error reading directory: %v", err)
	}

	// Array to store the resulting filenames
	var serviceFiles []string

	// Loop over the files and process them
	for _, file := range files {
		// Get the filename
		filename := file.Name()

		// Check if the file ends with ".yam
		if filename != "_" {
			// Append to the result array
			serviceFiles = append(serviceFiles, filename)
		}
	}

	return serviceFiles, nil
}

// Helper to create random strings
func randomToken(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		// pick a secure random index
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err) // or handle gracefully
		}
		b[i] = letters[num.Int64()]
	}
	return string(b)
}

func pre_process_request(r *http.Request, verbose bool) error {
	// Parse form (includes query params + POST form data)
	if err := r.ParseForm(); err != nil {
		log.Printf("error parsing request parameters: %s", err.Error())
		return err
	}

	if verbose {
		fmt.Println("\n=== Request Info ===")
		fmt.Printf("Method: %s\n", r.Method)
		fmt.Printf("URL: %s\n", r.URL.String())
		fmt.Printf("RemoteAddr: %s\n", r.RemoteAddr)

		fmt.Println("=== Request Headers ===")
		for name, values := range r.Header {
			for _, v := range values {
				fmt.Printf("%s: %s\n", name, v)
			}
		}

		fmt.Println("\n=== Request Parameters ===")
		for key, values := range r.Form {
			for _, v := range values {
				fmt.Printf("%s = %s\n", key, v)
			}
		}
	}

	return nil
}
