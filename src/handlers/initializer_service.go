package handlers

import (
	// "crypto/tls"
	// "crypto/x509"
	"fmt"
	// "time"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"identity.plus/mtls-gw/global"
	"identity.plus/mtls-gw/mtlsid"
	"identity.plus/mtls-gw/utils"
	// "os/exec"
	// "io"
	// "bytes"
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

	files, err := ioutil.ReadDir(global.Config__.DataDirectory + "/identity/_/service-id")
	if err != nil {
		return nil, fmt.Sprintf("error enrolling. identity not issued: %w", err)
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

func (srv *Initialization_Service) init_service(w http.ResponseWriter, r *http.Request) {
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
					Manager_Service__.Register(domain)
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

func (srv *Initialization_Service) Start() {
	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("webapp/static"))))
	mux.HandleFunc("/", srv.init_service)

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
