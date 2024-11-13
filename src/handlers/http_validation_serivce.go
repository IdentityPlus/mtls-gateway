package handlers

import (
	// "crypto/tls"
	// "crypto/x509"
	// "fmt"
	// "time"
	// "io/ioutil"
	"log"
	"net/http"

	// "html/template"
	"strings"
	// "mtls-gw/utils"
	"identity.plus/mtls-gw/global"
	// "mtls-gw/mtlsid"
	// "path/filepath"
	// "os"
	// "os/exec"
	// "io"
	// "bytes"
	"sync"
)

type Validation_Service struct {
	running bool
	mu      sync.Mutex
}

var Validation_Service__ = Validation_Service{running: false}

func (srv *Validation_Service) Running() bool {
	return srv.running
}

func (srv *Validation_Service) Start() {
	srv.mu.Lock()

	if srv.running {
		defer srv.mu.Unlock()
		return

	} else {
		srv.running = true
		srv.mu.Unlock()
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/validate/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodPost {
			log.Printf("validating: %s", r.URL)

			subject := r.URL.Path[len("/validate/"):]

			mtls_id := ""
			target_service := ""

			if strings.LastIndex(subject, "/") != -1 {
				mtls_id = subject[strings.LastIndex(subject, "/")+1:]
				target_service = subject[:strings.LastIndex(subject, "/")]
			} else {
				mtls_id = subject
			}

			// log.Printf("validating: %s at %s", mtls_id, target_service)

			api := Manager_Service__.Perimeter_APIs[target_service]

			if api != nil {
				validations, err := api.Validate_Client_Identity_SN(mtls_id, "", false)

				if err == "" {
					w.Write(validations.Raw)
				} else {
					http.Error(w, err, 500)
				}
			} else {
				w.Write([]byte("{\"Simple-Response\":{\"message\":\"No such service: " + target_service + "\",\"outcome\":\"ER 0000 Undetermined error\"}}"))
			}

		} else {
			http.Error(w, "unsupported method: "+r.Method, 403)
		}
	})

	secondaryServer := &http.Server{
		Addr:    "0.0.0.0:" + global.Config__.ValidationServicePort,
		Handler: mux,
	}

	log.Printf("Starting validation service HTTP server on http://localhost:%s...\n", global.Config__.ValidationServicePort)
	err := secondaryServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start secondary server: %v", err)
	}
}
