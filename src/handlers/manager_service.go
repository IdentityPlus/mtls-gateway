package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"identity.plus/mtls-gw/global"
	"identity.plus/mtls-gw/integrations"
	"identity.plus/mtls-gw/mtlsid"
	"identity.plus/mtls-gw/utils"

	// "path/filepath"
	"io"
	"os"
	"os/exec"

	// "bytes"
	"sync"
	"syscall"
)

type Manager_Service struct {
	Perimeter_APIs map[string]*mtlsid.Perimeter_API
	certificates   map[string]*tls.Certificate
	server         *http.Server
	running        bool
	mu             sync.Mutex
	openresty      *exec.Cmd
	Updated        string
}

var Manager_Service__ = Manager_Service{
	Perimeter_APIs: make(map[string]*mtlsid.Perimeter_API),
	running:        false,
}

func (srv *Manager_Service) Running() bool {
	return srv.running
}

func escape_slash(path string) string {
	return strings.ReplaceAll(path, "/", "-")
}

// Custom client authentication function
func (srv *Manager_Service) authenticate_client(domain string, cert *x509.Certificate) bool {
	// For now, just print certificate info. In a real scenario, add logic to verify the client certificate.
	var error_cause string
	var validation__ *mtlsid.Client_Validation_Ticket
	var device_name string
	var device_type string

	log.Printf("authenticating: %s", domain)
	validation__, device_name, device_type, error_cause = srv.Perimeter_APIs[domain].Validate_Client_Identity(cert, "", true)

	if error_cause != "" {
		log.Printf("Access denied to mTLS ID: {SN: %s, Agent: \"%s\"} on account of: %s\n", cert.SerialNumber.String(), cert.Subject.CommonName, error_cause)
		return false
	}

	var roles = ""
	var allowed = false

	for _, role := range validation__.Cache.ServiceRoles {

		if len(roles) > 0 {
			roles = roles + ", "
		}
		roles = roles + "\"" + role + "\""

		for _, allowed_role := range global.Config__.RolesAllowed {
			if !allowed && role == allowed_role {
				allowed = true
			}
		}
	}

	if allowed {
		log.Printf("Access granted to mTLS ID: {SN: %s, Agent: \"%s/%s\", Org-ID: \"%s\", Roles: [%s]}\n", validation__.Serial_No, device_name, device_type, validation__.Cache.OrgID, roles)
		return true
	} else {
		log.Printf("Access denied to mTLS ID: {SN: %s, Agent: \"%s/%s\", Org-ID: \"%s\", Roles: [%s]}\n", validation__.Serial_No, device_name, device_type, validation__.Cache.OrgID, roles)
		return false
	}

	return true
}

func (srv *Manager_Service) certificate_for(domain string, no_cache bool) *tls.Certificate {
	if srv.certificates == nil {
		srv.certificates = make(map[string]*tls.Certificate)
	}

	cert := srv.certificates[domain]

	if cert != nil && !no_cache {
		return cert
	}

	// Load the server certificate and key
	loaded_cert, err := tls.LoadX509KeyPair(
		global.Config__.DataDirectory+"/identity/"+domain+"/service-id/"+domain+".cer",
		global.Config__.DataDirectory+"/identity/"+domain+"/service-id/"+domain+".key")

	if err != nil {
		log.Printf("Failed to load server certificate and key: %v", err)
	}

	srv.certificates[domain] = &loaded_cert

	return &loaded_cert
}

func (srv *Manager_Service) load_TLS_config() *tls.Config {
	identities, _ := List_Service_Configurations()

	caCert, err := ioutil.ReadFile(global.Config__.DataDirectory + "/identity/" + identities[0] + "/service-id/identity-plus-root-ca.cer")
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	// Create a certificate pool with the CA certificate
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		// Dynamically retrieve certificates again in this specific config, if needed
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return srv.certificate_for(chi.ServerName, false), nil
		},
		// CA certificate pool
		ClientCAs: caCertPool,
		// Require client certificate
		ClientAuth: tls.RequireAnyClientCert,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			// Capture the SNI (domain name)
			domain := chi.ServerName

			// Return a new TLS config with the necessary certificates
			return &tls.Config{
				// Dynamically retrieve certificates again in this specific config, if needed
				GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return srv.certificate_for(domain, false), nil
				},
				ClientCAs:  caCertPool,               // CA certificate pool
				ClientAuth: tls.RequireAnyClientCert, // Require client certificate
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					// Parse the client's certificate from the raw bytes
					cert, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return fmt.Errorf("failed to parse client certificate: %v", err)
					}

					// Pass the domain (SNI) and certificate to the custom authentication function
					if !srv.authenticate_client(domain, cert) {
						return fmt.Errorf("client certificate authentication failed for domain: %s", domain)
					}

					return nil
				},
			}, nil
		},
	}

	return tlsConfig
}

func render_page(w http.ResponseWriter, tmpl string, data interface{}) {
	tmplPath := fmt.Sprintf("./webapp/templates/%s.html", tmpl)

	// Create the FuncMap before parsing the template files
	funcMap := template.FuncMap{
		"join":    utils.Join,
		"deslash": escape_slash,
	}

	// Parse templates and apply FuncMap
	parsedTemplate := template.Must(template.New("main").Funcs(funcMap).ParseFiles(
		"./webapp/templates/main.html",
		"./webapp/templates/header.html",
		tmplPath,
	))

	// Execute the template
	err := parsedTemplate.ExecuteTemplate(w, "main", data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		log.Printf("Error rendering template: %v\n", err)
	}
}

func (srv *Manager_Service) Register(domain string) {
	id_dir := global.Config__.DataDirectory + "/identity/" + domain

	api := mtlsid.Perimeter_API{
		Self_Authority: &mtlsid.Self_Authority_API{
			Verbose:      global.Config__.Verbose,
			Service:      global.Config__.IdentityBroker,
			Identity_Dir: id_dir,
			Device_Name:  global.Config__.DeviceName,
		},
	}

	srv.Perimeter_APIs[api.Domain()] = &api

	log.Printf("Registering Perimeter API for %s", api.Domain())
}

func (srv *Manager_Service) Start() {

	// prevent running multiple times
	srv.mu.Lock()

	if srv.running {
		defer srv.mu.Unlock()
		return

	} else {
		srv.running = true
		srv.mu.Unlock()
	}

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("webapp/static"))))
	mux.HandleFunc("/", srv.overview)
	mux.HandleFunc("/add-service-route/", srv.add_serivce_route)
	mux.HandleFunc("/basic-config/", srv.basic_config)
	mux.HandleFunc("/tcp-config/", srv.tcp_config)
	mux.HandleFunc("/http-config/", srv.http_config)
	mux.HandleFunc("/admin", srv.admin)

	tlsConfig := srv.load_TLS_config()

	// Create the HTTPS server with custom TLS configuration
	srv.server = &http.Server{
		Addr:      "0.0.0.0:" + global.Config__.AdminPort,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	global.Stats__.LaunchTime = time.Now()
	mtlsid.Stats__.TotalLatency = 0
	mtlsid.Stats__.ValidationLatency = 0
	mtlsid.Stats__.ValidationCount = 0

	log.Printf("Starting mTLS Gateway Manager service on port (https://%s:%s) with Identity Plus mTLS-based client authentication...\n", "0.0.0.0", global.Config__.AdminPort)
	err := srv.server.ListenAndServeTLS("", "") // Empty strings to use certificates from TLSConfig
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func (srv *Manager_Service) add_serivce_route(w http.ResponseWriter, r *http.Request) {
	op_domain, _, _ := net.SplitHostPort(r.Host)
	config := get_service_config(op_domain)

	var error_msg = ""
	var new_domain = ""
	var new_perimeter_api *mtlsid.Perimeter_API

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			error_msg = "Unable to parse form"
		}

		if r.FormValue("token") != "" {
			new_perimeter_api, error_msg = Enroll(r.FormValue("token"))

			if new_perimeter_api != nil {
				new_domain = new_perimeter_api.Domain()
				srv.Register(new_domain)
			}

		} else {
			error_msg = "no action specified"
		}
	}

	service_fonfigs, _ := List_Service_Configurations()

	render_page(w, "new-service", map[string]interface{}{
		"Domain":       srv.Perimeter_APIs[op_domain].Domain(),
		"SRV_Port":     fmt.Sprintf("%s", global.Config__.AdminAccessPort),
		"Error":        error_msg,
		"Destination":  new_domain,
		"Service":      config.Service,
		"Port":         global.Config__.AdminAccessPort,
		"CurrentPage":  "Add Service Route",
		"DynamicPages": service_fonfigs,
	})
}

func (srv *Manager_Service) admin(w http.ResponseWriter, r *http.Request) {
	domain, _, _ := net.SplitHostPort(r.Host)
	service_fonfigs, _ := List_Service_Configurations()

	render_page(w, "admin", map[string]interface{}{
		"CurrentPage":  "Admin",
		"SRV_Port":     fmt.Sprintf("%s", global.Config__.AdminAccessPort),
		"DynamicPages": service_fonfigs,
		"CacheSize":    srv.Perimeter_APIs[domain].Cache_Size(),
		"Domain":       srv.Perimeter_APIs[domain].Domain(),
	})
}

func (srv *Manager_Service) overview(w http.ResponseWriter, r *http.Request) {
	domain, port, _ := net.SplitHostPort(r.Host)
	config := get_service_config(domain)

	var validation__ *mtlsid.Client_Validation_Ticket
	var device_name string
	var device_type string

	cert := r.TLS.PeerCertificates[0]

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		if r.FormValue("action") == "Check Latency" {
			validation__, device_name, device_type, _ = srv.Perimeter_APIs[domain].Validate_Client_Identity(cert, "", false)

		} else if r.FormValue("action") == "Clear Cache" {
			srv.Perimeter_APIs[domain].Purge_Cache()
			validation__, device_name, device_type, _ = srv.Perimeter_APIs[domain].Validate_Client_Identity(cert, "", true)

		} else {
			log.Printf("unknown action: %s", r.FormValue("action"))
		}
	}

	if validation__ == nil {
		validation__, device_name, device_type, _ = srv.Perimeter_APIs[domain].Validate_Client_Identity(cert, "", true)
	}

	service_fonfigs, _ := List_Service_Configurations()

	render_page(w, "overview", map[string]interface{}{
		"CurrentPage":     "Overview",
		"SRV_Port":        fmt.Sprintf("%s", global.Config__.AdminAccessPort),
		"Port":            port,
		"DynamicPages":    service_fonfigs,
		"CacheSize":       srv.Perimeter_APIs[domain].Cache_Size(),
		"Domain":          srv.Perimeter_APIs[domain].Domain(),
		"Latency":         mtlsid.Stats__.ValidationLatency,
		"AvgLatency":      mtlsid.Stats__.TotalLatency / mtlsid.Stats__.ValidationCount,
		"ValidationCount": mtlsid.Stats__.ValidationCount,
		"UpTime":          utils.FormatDuration(global.Stats__.LaunchTime, time.Now()),
		"MtlsID":          validation__.Serial_No,
		"AgentName":       device_name,
		"Service":         config.Service,
		"AgentType":       device_type,
		"OrgID":           validation__.Cache.OrgID,
		"OrgRoles":        validation__.Cache.ServiceRoles,
		"Updated":         srv.Updated,
	})
}

func (srv *Manager_Service) basic_config(w http.ResponseWriter, r *http.Request) {
	domain, _, _ := net.SplitHostPort(r.Host)
	page_error := ""
	service_fonfigs, _ := List_Service_Configurations()
	config := get_service_config(domain)

	if r.Method == http.MethodPost {

		if r.FormValue("action") == "edit-interface" {
			config.Service.Port, _ = strconv.Atoi(r.FormValue("port"))
			config.Service.Mode = r.FormValue("mode")

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "add-worker" {
			config.Service.Upstream.Workers = append(config.Service.Upstream.Workers, r.FormValue("worker"))

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "remove-worker" {
			workers := config.Service.Upstream.Workers
			for i, worker := range workers {
				if worker == r.FormValue("worker") {
					config.Service.Upstream.Workers = append(workers[:i], workers[i+1:]...)
					break
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "rotate-client" {
			result := srv.Perimeter_APIs[domain].Self_Authority.Renew(false)
			if result != "renewed" {
				page_error = result
			}

		} else if r.FormValue("action") == "rotate-service" {
			result := srv.Perimeter_APIs[domain].Self_Authority.Issue_service_identity(true)
			if result != "renewed" {
				page_error = result
			}
			srv.certificate_for(domain, true)
			go srv.Start_Openresty()

		} else {
			log.Printf("unknown action: %s", r.FormValue("action"))
		}
	}

	var srv_agent_name, expires, renewal_due, client_serial, sv_srv_agent_name, sv_expires, sv_renewal_due, sv_client_serial string
	var age, sv_age int

	client_certificate, no_cc_err := srv.Perimeter_APIs[domain].Self_Authority.Client_Certificate()
	if no_cc_err == nil {
		x509_cert, _ := x509.ParseCertificate(client_certificate.Certificate[0])
		srv_agent_name = x509_cert.Subject.CommonName
		expires = x509_cert.NotAfter.Format("2006-01-02 15:04:05 MST")
		client_serial = x509_cert.SerialNumber.String()
		totalLifetime := x509_cert.NotAfter.Sub(x509_cert.NotBefore).Hours() / 24
		now := time.Now()
		elapsedDays := now.Sub(x509_cert.NotBefore).Hours() / 24
		age = int(elapsedDays / totalLifetime * 100)
		seventyFivePercentDays := totalLifetime * 0.75
		targetDate := x509_cert.NotBefore.Add(time.Duration(seventyFivePercentDays*24) * time.Hour)
		daysUntil75Percent := strconv.Itoa(int(math.Round(targetDate.Sub(now).Hours() / 24)))
		renewal_due = fmt.Sprintf("%s days", daysUntil75Percent)
	} else {
		srv_agent_name = no_cc_err.Error()
	}

	sv_client_certificate := srv.certificate_for(domain, false)
	x509_cert, _ := x509.ParseCertificate(sv_client_certificate.Certificate[0])
	sv_srv_agent_name = x509_cert.Subject.CommonName
	sv_expires = x509_cert.NotAfter.Format("2006-01-02 15:04:05 MST")
	sv_client_serial = x509_cert.SerialNumber.String()
	totalLifetime := x509_cert.NotAfter.Sub(x509_cert.NotBefore).Hours() / 24
	now := time.Now()
	elapsedDays := now.Sub(x509_cert.NotBefore).Hours() / 24
	sv_age = int(elapsedDays / totalLifetime * 100)
	seventyFivePercentDays := totalLifetime * 0.75
	targetDate := x509_cert.NotBefore.Add(time.Duration(seventyFivePercentDays*24) * time.Hour)
	daysUntil75Percent := strconv.Itoa(int(math.Round(targetDate.Sub(now).Hours() / 24)))
	sv_renewal_due = fmt.Sprintf("%s days", daysUntil75Percent)

	render_page(w, "my-service", map[string]interface{}{
		"CurrentPage":      "Basic Configuration",
		"SRV_Port":         fmt.Sprintf("%s", global.Config__.AdminAccessPort),
		"DynamicPages":     service_fonfigs,
		"Service":          config.Service,
		"Domain":           srv.Perimeter_APIs[domain].Domain(),
		"ClientSerial":     client_serial,
		"ServiceAgentName": srv_agent_name,
		"Expires":          expires,
		"RenewalDue":       renewal_due,
		"Age":              age,
		"ServerSerial":     sv_client_serial,
		"ServerCN":         sv_srv_agent_name,
		"ServerExpires":    sv_expires,
		"ServerRenewalDue": sv_renewal_due,
		"ServerAge":        sv_age,
		"PageError":        page_error,
	})
}

func (srv *Manager_Service) tcp_config(w http.ResponseWriter, r *http.Request) {
	domain, _, _ := net.SplitHostPort(r.Host)
	page_error := ""
	service_fonfigs, _ := List_Service_Configurations()
	config := get_service_config(domain)

	if r.Method == http.MethodPost {

		if r.FormValue("action") == "add-role" {
			config.Service.TCP.RolesAllowed = append(config.Service.TCP.RolesAllowed, r.FormValue("role"))
			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "remove-role" {
			roles := config.Service.TCP.RolesAllowed
			for i, role := range roles {
				if role == r.FormValue("role") {
					config.Service.TCP.RolesAllowed = append(roles[:i], roles[i+1:]...)
					break
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else {
			log.Printf("unknown action: %s", r.FormValue("action"))
		}
	}

	render_page(w, "my-service-tcp", map[string]interface{}{
		"CurrentPage":  "TCP Config",
		"SRV_Port":     fmt.Sprintf("%s", global.Config__.AdminAccessPort),
		"DynamicPages": service_fonfigs,
		"Service":      config.Service,
		"Domain":       srv.Perimeter_APIs[domain].Domain(),
		"PageError":    page_error,
	})
}

func (srv *Manager_Service) http_config(w http.ResponseWriter, r *http.Request) {
	domain, _, _ := net.SplitHostPort(r.Host)

	service_fonfigs, _ := List_Service_Configurations()
	config := get_service_config(domain)
	page_error := ""

	if r.Method == http.MethodPost {

		if r.FormValue("action") == "edit-mtls" {
			config.Service.HTTP.AccessMode = r.FormValue("split")

			if r.FormValue("mtlsid") != "" {
				config.Service.HTTP.MtlsID = r.FormValue("mtlsid")
			}
			if r.FormValue("agent") != "" {
				config.Service.HTTP.MtlsAgent = r.FormValue("agent")
			}
			if r.FormValue("org-id") != "" {
				config.Service.HTTP.MtlsOrgID = r.FormValue("org-id")
			}
			if r.FormValue("roles") != "" {
				config.Service.HTTP.MtlsRoles = r.FormValue("roles")
			}
			if r.FormValue("local-id") != "" {
				config.Service.HTTP.MtlsLocalID = r.FormValue("local-id")
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "edit-http" {
			config.Service.HTTP.Websockets = r.FormValue("ws") == "on"
			config.Service.HTTP.HostHeader = r.FormValue("host")

			if r.FormValue("xfw") != "" {
				config.Service.HTTP.XForwardedFor = r.FormValue("xfw")
			}
			if r.FormValue("xfwp") != "" {
				config.Service.HTTP.XForwardedProto = r.FormValue("xfwp")
			}
			if r.FormValue("xip") != "" {
				config.Service.HTTP.XRealIP = r.FormValue("xip")
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "change-path" {
			for i, location := range config.Service.HTTP.Locations {
				if location.Path == r.FormValue("path") {
					if r.FormValue("new-path") != "" {
						config.Service.HTTP.Locations[i].Path = r.FormValue("new-path")
					}

					break
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "change-custom" {
			for i, location := range config.Service.HTTP.Locations {
				if location.Path == r.FormValue("path") {
					if r.FormValue("custom") != "" {
						config.Service.HTTP.Locations[i].CustomCommands = r.FormValue("custom")
					}

					break
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "clone-location" {
			for _, location := range config.Service.HTTP.Locations {
				if location.Path == r.FormValue("path") {

					new_location := location
					new_location.Path = location.Path + "clone/"

					config.Service.HTTP.Locations = append(config.Service.HTTP.Locations, new_location)

					break
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "delete-location" {
			for i, location := range config.Service.HTTP.Locations {
				if location.Path == r.FormValue("path") {

					config.Service.HTTP.Locations = append(config.Service.HTTP.Locations[:i], config.Service.HTTP.Locations[i+1:]...)

					break
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "toggle-bypass" {
			for i, location := range config.Service.HTTP.Locations {
				if location.Path == r.FormValue("path") {

					config.Service.HTTP.Locations[i].Bypass = r.FormValue("bypass") != "on"

					break
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "add-location-role" {
			for i, location := range config.Service.HTTP.Locations {
				if location.Path == r.FormValue("path") {

					if r.FormValue("new-role") != "" {
						config.Service.HTTP.Locations[i].RolesAllowed = append(config.Service.HTTP.Locations[i].RolesAllowed, r.FormValue("new-role"))
					}

					break
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "remove-location-role" {
			if r.FormValue("role") != "" {
				for i, location := range config.Service.HTTP.Locations {
					if location.Path == r.FormValue("path") {
						for k, role := range config.Service.HTTP.Locations[i].RolesAllowed {
							if role == r.FormValue("role") {
								config.Service.HTTP.Locations[i].RolesAllowed = append(config.Service.HTTP.Locations[i].RolesAllowed[:k], config.Service.HTTP.Locations[i].RolesAllowed[k+1:]...)
								break
							}
						}

						break
					}
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else {
			log.Printf("unknown action: %s", r.FormValue("action"))
		}
	}

	render_page(w, "my-service-http", map[string]interface{}{
		"CurrentPage":  "HTTP Config",
		"SRV_Port":     fmt.Sprintf("%s", global.Config__.AdminAccessPort),
		"DynamicPages": service_fonfigs,
		"Service":      config.Service,
		"Domain":       srv.Perimeter_APIs[domain].Domain(),
		"PageError":    page_error,
	})
}

func (srv *Manager_Service) update_service_config(domain string, config integrations.ServiceConfig) string {
	integrations.Write_Service_Config(global.Config__.DataDirectory+"/services/"+domain+".yaml", config)

	nginx_template := integrations.Nginx_Builder{
		Domain:          domain,
		MtlsIdDirectory: global.Config__.DataDirectory,
		Service:         config.Service,
	}

	lb_cfg := nginx_template.Build()

	// deploy test environment
	utils.WriteToFile(global.Config__.DataDirectory+"/services/work/nginx.conf", []byte(integrations.Build_Nginx("/services/work")))

	utils.DeleteConfFiles(global.Config__.DataDirectory + "/services/work/conf/stream/")
	utils.DeleteConfFiles(global.Config__.DataDirectory + "/services/work/conf/http/")

	destination_file := ""

	if config.Service.Mode == "TCP" {
		os.MkdirAll(global.Config__.DataDirectory+"/conf/stream/", 0755)
		destination_file = "/conf/stream/" + domain + ".conf"
	} else {
		os.MkdirAll(global.Config__.DataDirectory+"/conf/http/", 0755)
		destination_file = "/conf/http/" + domain + ".conf"
	}

	utils.WriteToFile(global.Config__.DataDirectory+"/services/work"+destination_file, []byte(lb_cfg))
	test_result := nginx_template.Openresty_Test_Config(global.Config__.DataDirectory + "/services/work/nginx.conf")

	// in case no errors have been found
	// copy the modified configuration file into the production directory
	if test_result == "" {
		err := utils.MoveFile(global.Config__.DataDirectory+"/services/work"+destination_file, global.Config__.DataDirectory+destination_file)
		if err == nil {
			go srv.Start_Openresty()
		} else {
			log.Printf("Error moving config file: %v\n", err)
		}
	}

	// log.Printf("test resuts: %s\n", test_result)

	return test_result
}

func (srv *Manager_Service) Start_Openresty() {
	if srv.openresty != nil {
		fmt.Printf("Openresty already running. Sending reload signal ...\n")
		if err := srv.openresty.Process.Signal(syscall.SIGHUP); err != nil {
			log.Printf("Error reloading %v ...\n", err)
		}

		return
	}

	log.Printf("Starting Openresty HTTP/TCP Proxy Server with config: %s", global.Config__.DataDirectory+"/conf/nginx.conf")

	// configure_openresty();
	utils.WriteToFile(global.Config__.DataDirectory+"/conf/nginx.conf", []byte(integrations.Build_Nginx("")))

	// Command to start (replace with your own)
	srv.openresty = exec.Command("/usr/local/openresty/bin/openresty", "-g", "daemon off;", "-c", global.Config__.DataDirectory+"/conf/nginx.conf")

	// Get the output pipe (stdout and stderr)
	stdout, err := srv.openresty.StdoutPipe()
	if err != nil {
		fmt.Printf("Error getting stdout: %v\n", err)
		return
	}
	stderr, err := srv.openresty.StderrPipe()
	if err != nil {
		fmt.Printf("Error getting stderr: %v\n", err)
		return
	}

	// Start the command
	err = srv.openresty.Start()
	if err != nil {
		fmt.Printf("Error starting command: %v\n", err)
		return
	}

	// Copy stdout and stderr to the console
	go io.Copy(os.Stdout, stdout) // Redirect stdout to console
	go io.Copy(os.Stderr, stderr) // Redirect stderr to console

	// Wait for the command to complete
	err = srv.openresty.Wait()
	if err != nil {
		fmt.Printf("Command finished with error: %v\n", err)
	} else {
		fmt.Println("Command finished successfully!")
	}

	fmt.Printf("Openresty exit ... \n")
	srv.openresty = nil
}

func get_service_config(domain string) integrations.ServiceConfig {
	config, err := integrations.Parse_Service_Config(global.Config__.DataDirectory + "/services/" + domain + ".yaml")

	if err != nil {
		log.Printf("No config file for %s, initializting service", domain)
		config = integrations.ServiceConfig{
			Service: integrations.ManagedService{
				Port: 443,
				Mode: "HTTP",
				Upstream: integrations.Upstream{
					Workers: []string{("w1." + domain + ":8080")},
				},
				TCP: integrations.Tcp{
					RolesAllowed: []string{"org. administrator", "administrator"},
				},
				HTTP: integrations.Http{
					AccessMode:      "Gateway",
					Websockets:      false,
					HostHeader:      "",
					XForwardedFor:   "X-Forwarded-For",
					XForwardedProto: "X-Forwarded-Proto",
					XRealIP:         "X-Real-IP",
					MtlsID:          "X-mTLS-ID",
					MtlsAgent:       "X-mTLS-Agent",
					MtlsOrgID:       "X-mTLS-Org-ID",
					MtlsRoles:       "X-mTLS-Roles",
					MtlsLocalID:     "X-mTLS-Local-ID",
					Locations: []integrations.Location{
						integrations.Location{
							Path:           "/",
							Bypass:         false,
							RolesAllowed:   []string{"org. administrator", "administrator"},
							CustomCommands: "# Nginx custom location scope commands",
						},
					},
				},
			},
		}

		integrations.Write_Service_Config(global.Config__.DataDirectory+"/services/"+domain+".yaml", config)
	}

	return config
}
