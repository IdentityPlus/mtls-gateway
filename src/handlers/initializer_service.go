package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"identity.plus/mtls-gw/global"
	"identity.plus/mtls-gw/mtlsid"
	"identity.plus/mtls-gw/utils"
)

type Initialization_Service struct {
	running bool
}

var Initialization_Service__ = Initialization_Service{running: false}

func Enroll(token string) (*mtlsid.Perimeter_API, string) {

	var cli = mtlsid.Self_Authority_API{
		Verbose:      true,
		Service:      global.Config__.IdentityBroker,
		Identity_Dir: global.Config__.DataDirectory + "/identity/_",
		Device_Name:  global.Config__.DeviceName,
	}

	ans := cli.Enroll_unified(token)

	if strings.HasPrefix(ans, "Failed ") {
		return nil, ans
	}

	cli.Invalidate()
	ans = cli.Issue_service_identity(true)

	if strings.HasPrefix(ans, "Failed ") {
		return nil, ans
	}

	ans = cli.Get_trust_chain()

	if strings.HasPrefix(ans, "Failed ") {
		return nil, ans
	}

	files, err := os.ReadDir(global.Config__.DataDirectory + "/identity/_/service-id")
	if err != nil {
		return nil, fmt.Sprintf("error enrolling. identity not issued: %v", err)
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

	// move identity in its own directory
	if domain != "" {
		sourceDir := filepath.Join(global.Config__.DataDirectory, "identity", "_")
		destDir := filepath.Join(global.Config__.DataDirectory, "identity", domain)

		if err := os.Rename(sourceDir, destDir); err != nil {
			return nil, fmt.Sprintf("failed to move file: %v", err)
		}

		// recreate the temp working _ directory
		os.MkdirAll(sourceDir, 0755)

		// make sure the api's identity dir is moved too
		cli.Identity_Dir = destDir
		return &mtlsid.Perimeter_API{
			Self_Authority: &cli,
		}, ""
	}

	return nil, "Initialization failed for unknown reason. Please contact us for potential fixes."
}

func (srv *Initialization_Service) render_page(w http.ResponseWriter, tmpl string, data interface{}) {
	tmplPath := fmt.Sprintf("./webapp/templates/%s.html", tmpl)

	// Create the FuncMap before parsing the template files
	funcMap := template.FuncMap{
		"join": utils.Join,
	}

	// Parse templates and apply FuncMap
	parsedTemplate := template.Must(template.New("init").Funcs(funcMap).ParseFiles(
		"./webapp/templates/init.html",
		"./webapp/templates/header.html",
		tmplPath,
	))

	// Execute the template
	err := parsedTemplate.ExecuteTemplate(w, "init", data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		log.Printf("Error rendering template: %v\n", err)
	}
}

func (srv *Initialization_Service) handle_init_service(w http.ResponseWriter, r *http.Request) {

	if global.Intialized {
		host := r.Host
		if i := strings.Index(host, ":"); i != -1 {
			host = host[:i]
		}

		target := "https://" + host

		if global.Config__.ApplicationPort != 443 {
			target += ":" + strconv.Itoa(global.Config__.ApplicationPort)
		}

		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusFound)

		return
	}

	var perimeter_api *mtlsid.Perimeter_API
	var error_msg = ""
	var domain = ""
	var header = "not initialized"

	if len(Manager_Service__.Perimeter_APIs) > 0 {
		for k := range Manager_Service__.Perimeter_APIs {
			domain = Manager_Service__.Perimeter_APIs[k].Domain()
			break
		}
		header = domain
	} else {
		if r.Method == http.MethodPost {
			err := r.ParseForm()
			if err != nil {
				error_msg = "Unable to parse form"
			}

			if r.FormValue("token") != "" {
				perimeter_api, error_msg = Enroll(r.FormValue("token"))

				if perimeter_api != nil {
					domain = perimeter_api.Domain()
					Manager_Service__.Register_Service(domain)
					go Manager_Service__.Start()
				}

			} else {
				error_msg = "no action specified"
			}
		}
	}

	srv.render_page(w, "new-service", map[string]interface{}{
		"Domain":      header,
		"Error":       error_msg,
		"Destination": domain,
		"Port":        global.Config__.AdminPort,
	})
}

func handle_download_ca(w http.ResponseWriter, r *http.Request) {
	configurations := Manager_Service__.Get_Configurations()

	if len(configurations) == 0 {
		fmt.Fprintln(w, "mTLS Gatewat is not yet initialized, the CA has not yet been saved locally.")
		return
	}

	root_ca_data, err := os.ReadFile(global.Config__.DataDirectory + "/identity/" + configurations[0] + "/service-id/identity-plus-root-ca.cer")
	if err != nil {
		log.Printf("Error loading %s: %v", global.Config__.DataDirectory+"/identity/"+configurations[0]+"/service-id/identity-plus-root-ca.cer", err)
	}

	var roots []byte
	var block *pem.Block
	for {
		block, root_ca_data = pem.Decode(root_ca_data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // skip malformed certs
		}

		// 3️⃣ Detect if this cert is self-signed (issuer == subject)
		if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
			// Likely a root CA
			roots = pem.EncodeToMemory(block)
		}
	}

	if len(roots) == 0 {
		http.Error(w, "No root CA found in PEM", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\"identity-plus-root-ca.cer")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(roots)))
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(roots)
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func handle_acme_challenges(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if i := strings.Index(host, ":"); i != -1 {
		host = host[:i]
	}

	challenge := r.URL.RequestURI()[len("/.well-known/acme-challenge/"):]

	data, error := os.ReadFile(global.Config__.DataDirectory + "/letsencrypt/acme-challenge/" + host + "/" + challenge)

	if error != nil {
		log.Printf("Unable to load: %s\n", global.Config__.DataDirectory+"/letsencrypt/acme-challenge/"+host+"/"+challenge)
		target := "https://" + host

		if global.Config__.ApplicationPort != 443 {
			target += ":" + strconv.Itoa(global.Config__.ApplicationPort)
		}

		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusFound)
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

func (srv *Initialization_Service) Start() {
	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("webapp/static"))))
	mux.HandleFunc("/download-ca", handle_download_ca)
	mux.HandleFunc("/.well-known/acme-challenge/", handle_acme_challenges)
	mux.HandleFunc("/", srv.handle_init_service)

	initialization_servive := &http.Server{
		Addr:    "0.0.0.0:80",
		Handler: mux,
	}

	log.Printf("Starting initialization service over HTTP: http://ip-address/ ...\n")
	err := initialization_servive.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start initialization service: %v", err)
	}
}
