package handlers

import (
	// "crypto/tls"
	// "crypto/x509"

	// "io/ioutil"
	"log"
	"net/http"
	"strings"

	// "html/template"

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

type Authenticator_Service struct {
	running bool
	mu      sync.Mutex
}

var Validation_Service__ = Authenticator_Service{running: false}

var (
	OIDC_Authenticator__ = make(map[string]*OIDC_Authenticator)
	oidcMu               sync.Mutex
)

func (srv *Authenticator_Service) Running() bool {
	return srv.running
}

func (srv *Authenticator_Service) Start() {
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
	mux.HandleFunc("/mtls-gw/validate/", handle_mtls_id_validation)
	mux.HandleFunc("/", srv.handle_everything_else)

	secondaryServer := &http.Server{
		Addr:    "0.0.0.0:" + global.Config__.AuthenticatorOperatingPort,
		Handler: mux,
	}

	log.Printf("Starting validation service HTTP server on http://localhost:%s...\n", global.Config__.AuthenticatorOperatingPort)
	err := secondaryServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start secondary server: %v", err)
	}
}

/**
 * Start the OIDC discovery process
 */
func (srv *Authenticator_Service) handle_everything_else(w http.ResponseWriter, r *http.Request) {
	//dynamically catch paths and decide handlers

	if strings.HasPrefix(r.URL.Path, "/mtls-gw/oidc/") {
		srv.handle_oidc(w, r)

	} else {
		// Parse form (includes query params + POST form data)
		// We print things and capture the fact that a 404 URL was hit
		err := pre_process_request(r, true)
		if err != nil {
			http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("nothing here ..."))
	}
}

// --- Handlers ---
func (srv *Authenticator_Service) handle_oidc(w http.ResponseWriter, r *http.Request) {
	var prefix = r.URL.Path
	prefix = prefix[len("/mtls-gw/oidc/"):]
	var service string

	if prefix == "auth" {
		service = r.Host
		prefix = "auth"
	} else {
		service = prefix[0:strings.Index(prefix, "/")]
		prefix = prefix[len(service)+1:]
	}

	// select the OIDC Authenticator for the right service
	auth := srv.Get_OIDC_Authenticator(service)

	if prefix == "auth" {
		auth.handle_OAuth2_login(w, r)
	} else if prefix == "token" {
		auth.handle_oidc_authorization(w, r)
	} else if prefix == "userinfo" {
		auth.handle_oidc_user_info(w, r)
	} else if prefix == "jwks" {
		auth.handle_oidc_jwks(w, r)
	} else {
		auth.handle_oidc_configuration(w, r)
	}
}

func (srv *Authenticator_Service) Get_OIDC_Authenticator(domain string) *OIDC_Authenticator {
	oidcMu.Lock()
	defer oidcMu.Unlock()
	auth := OIDC_Authenticator__[domain]
	if auth == nil {
		auth = NewOIDC_Authenticator(domain, Manager_Service__.Get_Service_Config(domain).Service)
		OIDC_Authenticator__[domain] = auth
	}

	return auth
}
