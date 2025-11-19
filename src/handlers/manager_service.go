package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"regexp"
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
	Perimeter_APIs      map[string]*mtlsid.Perimeter_API
	certificates        map[string]*tls.Certificate
	server              *http.Server
	running             bool
	mu                  sync.Mutex
	openresty           *exec.Cmd
	Updated             string
	configuration_files []string
	managed_services    map[string]*integrations.ServiceConfig
}

var Manager_Service__ = Manager_Service{
	Perimeter_APIs:   make(map[string]*mtlsid.Perimeter_API),
	managed_services: make(map[string]*integrations.ServiceConfig),
	running:          false,
}

func (srv *Manager_Service) Get_Configurations() []string {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.configuration_files) == 0 {
		srv.configuration_files, _ = List_Service_Configurations()
	}

	return srv.configuration_files
}

func (srv *Manager_Service) Running() bool {
	return srv.running
}

func escape_slash(path string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_-]+`)
	return re.ReplaceAllString(path, "-")
}

func (srv *Manager_Service) authenticate_client(domain string, cert *x509.Certificate) bool {
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
		log.Printf("Access Granted: {domain: \"%s\", mTLS ID: %s, Agent: \"%s/%s\", Org-ID: \"%s\", Roles: [%s]}\n", domain, validation__.Serial_No, device_name, device_type, validation__.Cache.OrgID, roles)
		return true
	} else {
		log.Printf("Access Denied: {domain: \"%s\", mTLS ID: %s, Agent: \"%s/%s\", Org-ID: \"%s\", Roles: [%s]}\n", domain, validation__.Serial_No, device_name, device_type, validation__.Cache.OrgID, roles)
		return false
	}
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
	identities := srv.Get_Configurations()

	caCert, err := os.ReadFile(global.Config__.DataDirectory + "/identity/" + identities[0] + "/service-id/identity-plus-root-ca.cer")
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
		log.Printf("Error rendering template %s: %v\n", tmpl, err)
	}
}

func (srv *Manager_Service) Register_Service(domain string) {
	srv.Configure_Perimeter_API(domain)

	srv.mu.Lock()
	defer srv.mu.Unlock()

	Manager_Service__.configuration_files = nil
}

func (srv *Manager_Service) Configure_Perimeter_API(domain string) {
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
	mux.HandleFunc("/", srv.handle_overview)
	mux.HandleFunc("/download-ca", handle_download_ca)
	mux.HandleFunc("/add-service-route/", srv.handle_new_serivce_route)
	mux.HandleFunc("/routes/", srv.handle_routes)
	mux.HandleFunc("/access-control/", srv.handle_access_control)
	mux.HandleFunc("/tcp-config/", srv.handle_tcp_config)
	mux.HandleFunc("/http-config/", srv.handle_http_config)
	mux.HandleFunc("/admin", srv.handle_admin)
	mux.HandleFunc("/logs", srv.handle_logs)
	mux.HandleFunc("/view-log", srv.handle_log_view)
	mux.HandleFunc("/dl-log-file", srv.handle_download_log_file)

	tlsConfig := srv.load_TLS_config()

	// Create the HTTPS server with custom TLS configuration
	srv.server = &http.Server{
		Addr:      "0.0.0.0:" + strconv.Itoa(global.Config__.AdminOperatingPort),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	global.Stats__.LaunchTime = time.Now()
	mtlsid.Stats__.TotalLatency = 0
	mtlsid.Stats__.ValidationLatency = 0
	mtlsid.Stats__.ValidationCount = 0

	log.Printf("Starting mTLS Gateway Manager service on port (https://%s:%v) with Identity Plus mTLS-based client authentication...\n", "0.0.0.0", global.Config__.AdminOperatingPort)
	err := srv.server.ListenAndServeTLS("", "") // Empty strings to use certificates from TLSConfig
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func (srv *Manager_Service) handle_new_serivce_route(w http.ResponseWriter, r *http.Request) {
	service_fonfigs := srv.Get_Configurations()
	op_domain, _, _ := net.SplitHostPort(r.Host)
	config := srv.Get_Service_Config(op_domain)

	var error_msg = ""
	var new_domain = ""
	var host_ip = ""

	ips, _ := net.LookupIP(op_domain)

	if len(ips) > 0 {
		host_ip = ips[0].String()
	}
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
				srv.Register_Service(new_domain)
			}

		} else {
			error_msg = "no action specified"
		}
	}

	render_page(w, "new-service", map[string]interface{}{
		"Domain":       op_domain,
		"Host_IP":      host_ip,
		"SRV_Port":     global.Config__.AdminPort,
		"Error":        error_msg,
		"Destination":  new_domain,
		"Service":      config.Service,
		"Port":         global.Config__.AdminPort,
		"CurrentPage":  "Add Service Route",
		"DynamicPages": service_fonfigs,
	})
}

func atoi(s string, def int) int {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}

	return def
}

func (srv *Manager_Service) handle_admin(w http.ResponseWriter, r *http.Request) {
	service_fonfigs := srv.Get_Configurations()
	op_domain, _, _ := net.SplitHostPort(r.Host)
	config := srv.Get_Service_Config(op_domain)
	var error_msg = ""

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			error_msg = "Unable to parse form"
		}

		if r.FormValue("action") == "edit-config" {

			ttl, _ := strconv.Atoi(r.FormValue("mtls_id_ttl"))
			if ttl <= 0 {
				ttl = 5
			}

			new_cfg := global.Config{
				ApplicationPort:            atoi(r.FormValue("application_port"), global.Config__.ApplicationPort),
				ApplicationOperatingPort:   atoi(r.FormValue("application_operating_port"), global.Config__.ApplicationOperatingPort),
				AdminPort:                  atoi(r.FormValue("admin_port"), global.Config__.AdminPort),
				AdminOperatingPort:         atoi(r.FormValue("admin_operating_port"), global.Config__.AdminOperatingPort),
				LocalAuthenticatorEndpoint: r.FormValue("local_authenticator_endpoint"),
				AuthenticatorOperatingPort: atoi(r.FormValue("authenticator_operating_port"), global.Config__.AuthenticatorOperatingPort),
				MtlsIdTtl:                  ttl,
				Verbose:                    global.Config__.Verbose,
				DataDirectory:              global.Config__.DataDirectory,
				DeviceName:                 global.Config__.DeviceName,
				RolesAllowed:               global.Config__.RolesAllowed,
				IdentityBroker:             global.Config__.IdentityBroker,
			}

			global.Config__ = &new_cfg

			error := global.Config__.Save("/etc/mtls-gateway/config.yaml")
			if error != nil {
				error_msg = error.Error()
			}

		} else if r.FormValue("action") == "restart" {
			defer func() {
				time.Sleep(500 * time.Millisecond)
				os.Exit(0)
			}()

		} else {
			error_msg = "no action specified"
		}
	}

	render_page(w, "admin", map[string]interface{}{
		"CurrentPage":  "Admin",
		"Domain":       "All Services",
		"SRV_Port":     global.Config__.AdminPort,
		"Port":         global.Config__.ApplicationPort,
		"Error":        error_msg,
		"Service":      config.Service,
		"DynamicPages": service_fonfigs,
		"Config":       global.Config__,
	})

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (srv *Manager_Service) handle_download_log_file(w http.ResponseWriter, r *http.Request) {
	var log_content = ""

	err := r.ParseForm()
	if err != nil {
		log_content = "Unable to parse form"
	}

	if log_content == "" && r.FormValue("file") != "" {
		log_content, _ = utils.Log_Writer.Tail(r.FormValue("file"), int64(atoi(r.FormValue("pos"), 0)))
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	_, err = w.Write([]byte(log_content))

	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func (srv *Manager_Service) handle_logs(w http.ResponseWriter, r *http.Request) {
	service_fonfigs := srv.Get_Configurations()
	op_domain, _, _ := net.SplitHostPort(r.Host)
	config := srv.Get_Service_Config(op_domain)
	var error_msg = ""

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			error_msg = "Unable to parse form"
		}

		if r.FormValue("action") == "edit-config" {
			global.Config__.Verbose = r.FormValue("verbose") == "on"
			global.Config__.Log_Retention = atoi(r.FormValue("log-retention"), global.Config__.Log_Retention)

			error := global.Config__.Save("/etc/mtls-gateway/config.yaml")
			if error != nil {
				error_msg = error.Error()
			}

		} else if r.FormValue("action") == "delete" {
			for key := range r.Form {
				if strings.HasPrefix(key, "tick-") {
					f := key[len("tick-"):]
					log.Println("Deleting: " + f)
					error_msg = utils.Log_Writer.Delete(f)
				}
			}
		} else {
			error_msg = "no action specified"
		}
	}

	log_files, _ := utils.Log_Writer.List()

	render_page(w, "logs", map[string]interface{}{
		"CurrentPage":  "Logs",
		"Domain":       "All Services",
		"SRV_Port":     global.Config__.AdminPort,
		"Port":         global.Config__.ApplicationPort,
		"PageError":    error_msg,
		"Service":      config.Service,
		"DynamicPages": service_fonfigs,
		"Config":       global.Config__,
		"Files":        log_files,
		"Log_File":     log_files[0],
	})

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (srv *Manager_Service) handle_log_view(w http.ResponseWriter, r *http.Request) {
	service_fonfigs := srv.Get_Configurations()
	op_domain, _, _ := net.SplitHostPort(r.Host)
	config := srv.Get_Service_Config(op_domain)
	var error_msg = ""

	err := r.ParseForm()
	if err != nil {
		error_msg = "Unable to parse form"
	}

	render_page(w, "view-log", map[string]interface{}{
		"CurrentPage":  "View Log",
		"Domain":       "All Services",
		"SRV_Port":     global.Config__.AdminPort,
		"Port":         global.Config__.ApplicationPort,
		"PageError":    error_msg,
		"Service":      config.Service,
		"DynamicPages": service_fonfigs,
		"Config":       global.Config__,
		"Log_File":     r.FormValue("file"),
	})

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (srv *Manager_Service) handle_overview(w http.ResponseWriter, r *http.Request) {
	service_fonfigs := srv.Get_Configurations()
	domain, _, _ := net.SplitHostPort(r.Host)
	config := srv.Get_Service_Config(domain)

	var validation__ *mtlsid.Client_Validation_Ticket
	var device_name, client_serial, device_type, srv_agent_name, renewal_due, expires string
	var age int

	cert := r.TLS.PeerCertificates[0]

	client_certificate, no_cc_err := srv.Perimeter_APIs[domain].Self_Authority.Client_Certificate()
	if no_cc_err == nil {
		x509_cert, _ := x509.ParseCertificate(client_certificate.Certificate[0])
		client_serial = x509_cert.SerialNumber.String()
		srv_agent_name = x509_cert.Subject.CommonName
		expires = x509_cert.NotAfter.Format("2006-01-02 15:04:05 MST")

		totalLifetime := x509_cert.NotAfter.Sub(x509_cert.NotBefore).Hours() / 24
		now := time.Now()
		seventyFivePercentDays := totalLifetime * 0.75
		targetDate := x509_cert.NotBefore.Add(time.Duration(seventyFivePercentDays*24) * time.Hour)
		daysUntil75Percent := strconv.Itoa(int(math.Round(targetDate.Sub(now).Hours() / 24)))
		renewal_due = fmt.Sprintf("%s days", daysUntil75Percent)

		elapsedDays := now.Sub(x509_cert.NotBefore).Hours() / 24
		age = int(elapsedDays / totalLifetime * 100)

	} else {
		srv_agent_name = no_cc_err.Error()
	}

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

	render_page(w, "overview", map[string]interface{}{
		"CurrentPage":     "Overview",
		"SRV_Port":        global.Config__.AdminPort,
		"Port":            global.Config__.ApplicationPort,
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
		"OrgName":         validation__.Cache.OrgName,
		"OrgEmail":        validation__.Cache.OrgEmail,
		"OrgRoles":        validation__.Cache.ServiceRoles,
		"Updated":         srv.Updated,

		"Age":              age,
		"ClientSerial":     client_serial,
		"ServiceAgentName": srv_agent_name,
		"Expires":          expires,
		"RenewalDue":       renewal_due,
	})
}

func (srv *Manager_Service) handle_routes(w http.ResponseWriter, r *http.Request) {
	domain, _, _ := net.SplitHostPort(r.Host)
	page_error := ""
	service_fonfigs := srv.Get_Configurations()
	config := srv.Get_Service_Config(domain)

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

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

	var sv_srv_agent_name, sv_expires, sv_renewal_due, sv_client_serial string
	var sv_age int

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

	render_page(w, "routes", map[string]interface{}{
		"CurrentPage":      "Routes",
		"SRV_Port":         global.Config__.AdminPort,
		"DynamicPages":     service_fonfigs,
		"Service":          config.Service,
		"Domain":           srv.Perimeter_APIs[domain].Domain(),
		"ServerSerial":     sv_client_serial,
		"ServerCN":         sv_srv_agent_name,
		"ServerExpires":    sv_expires,
		"ServerRenewalDue": sv_renewal_due,
		"ServerAge":        sv_age,
		"PageError":        page_error,
	})
}

func (srv *Manager_Service) handle_tcp_config(w http.ResponseWriter, r *http.Request) {
	domain, _, _ := net.SplitHostPort(r.Host)
	page_error := ""
	service_fonfigs := srv.Get_Configurations()
	config := srv.Get_Service_Config(domain)

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

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
		"SRV_Port":     global.Config__.AdminPort,
		"DynamicPages": service_fonfigs,
		"Service":      config.Service,
		"Domain":       srv.Perimeter_APIs[domain].Domain(),
		"PageError":    page_error,
	})
}

func (srv *Manager_Service) handle_access_control(w http.ResponseWriter, r *http.Request) {
	service_fonfigs := srv.Get_Configurations()
	domain, _, _ := net.SplitHostPort(r.Host)
	config := srv.Get_Service_Config(domain)

	cert := r.TLS.PeerCertificates[0]
	var validation__, _, _, _ = srv.Perimeter_APIs[domain].Validate_Client_Identity(cert, "", true)

	if config.Service.HTTP.OIDC.Clients == nil {
		config.Service.HTTP.OIDC.Clients = []integrations.OIDC_Client{integrations.OIDC_Client{
			Id:     "client1",
			Secret: randomToken(16),
		}}
	}
	page_error := ""

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		if r.FormValue("action") == "edit-mtls" {
			config.Service.HTTP.AccessMode = r.FormValue("split")

			if r.FormValue("mtlsid") != "" {
				config.Service.HTTP.MtlsID = r.FormValue("mtlsid")
			}
			if r.FormValue("agent") != "" {
				config.Service.HTTP.MtlsAgent = r.FormValue("agent")
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "edit-trusted-proxy" {
			if r.FormValue("org-id") != "" {
				config.Service.HTTP.Trusted_Headers.MtlsOrgID = r.FormValue("org-id")
			}
			if r.FormValue("org-name") != "" {
				config.Service.HTTP.Trusted_Headers.MtlsOrgName = r.FormValue("org-name")
			}
			if r.FormValue("org-email") != "" {
				config.Service.HTTP.Trusted_Headers.MtlsOrgEmail = r.FormValue("org-email")
			}
			if r.FormValue("roles") != "" {
				config.Service.HTTP.Trusted_Headers.MtlsRoles = r.FormValue("roles")
			}
			if r.FormValue("local-id") != "" {
				config.Service.HTTP.Trusted_Headers.MtlsLocalID = r.FormValue("local-id")
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "edit-oidc" {

			for key := range r.Form {
				if strings.HasPrefix(key, "client-name-") {
					c := key[len("client-name-"):]
					for i, client := range config.Service.HTTP.OIDC.Clients {
						if escape_slash(client.Id) == c {
							new_name := r.FormValue(key)
							new_secret := r.FormValue("client-secret-" + c)

							if new_name == "" {
								config.Service.HTTP.OIDC.Clients = append(config.Service.HTTP.OIDC.Clients[:i], config.Service.HTTP.OIDC.Clients[i+1:]...)
								break
							}

							if new_secret == "" {
								new_secret = randomToken(16)
							}

							config.Service.HTTP.OIDC.Clients[i].Id = new_name
							config.Service.HTTP.OIDC.Clients[i].Secret = new_secret
						}
					}
				}
			}

			id := r.FormValue("new-client-name")
			secret := r.FormValue("new-client-secret")

			if id != "" {
				if secret == "" {
					secret = randomToken(16)
				}

				config.Service.HTTP.OIDC.Clients = append(config.Service.HTTP.OIDC.Clients, integrations.OIDC_Client{
					Id:     id,
					Secret: secret,
				})

			} else if id == "" && secret != "" {
				page_error = "Client ID must be specified."
			}

			// continue processeing
			if page_error == "" {
				page_error = srv.update_service_config(domain, config)
			}

		} else if r.FormValue("action") == "edit-mapped-roles" {

			for key := range r.Form {
				if strings.HasPrefix(key, "role-from-") {
					c := key[len("role-from-"):]
					for i, mapping := range config.Service.HTTP.Translator.Mappings {
						if escape_slash(mapping.Canonical) == c {
							new_canonical := r.FormValue(key)
							new_local := r.FormValue("role-to-" + c)

							if new_canonical == "" || new_local == "" {
								config.Service.HTTP.Translator.Mappings = append(config.Service.HTTP.Translator.Mappings[:i], config.Service.HTTP.Translator.Mappings[i+1:]...)
								break
							}

							config.Service.HTTP.Translator.Mappings[i].Canonical = new_canonical
							config.Service.HTTP.Translator.Mappings[i].Local = new_local
						}

					}
				}

			}

			canonical := r.FormValue("new-role-from")
			local := r.FormValue("new-role-to")

			if canonical != "" {
				if local == "" {
					local = canonical
				}

				config.Service.HTTP.Translator.Mappings = append(config.Service.HTTP.Translator.Mappings, integrations.Role_Mapping{
					Canonical: canonical,
					Local:     local,
				})

			} else if canonical == "" && local != "" {
				page_error = "Both canonical and local roles must be specified."
			}

			// continue processeing
			if page_error == "" {
				page_error = srv.update_service_config(domain, config)
			}

		} else {
			log.Printf("unknown action: %s", r.FormValue("action"))
		}
	}

	render_page(w, "my-service-access-ctl", map[string]interface{}{
		"CurrentPage":    "Access Control",
		"SRV_Port":       global.Config__.AdminPort,
		"Local_Endpoint": global.Config__.LocalAuthenticatorEndpoint,
		"DynamicPages":   service_fonfigs,
		"Service":        config.Service,
		"Domain":         srv.Perimeter_APIs[domain].Domain(),
		"App_Port":       global.Config__.ApplicationPort,
		"PageError":      page_error,
		"OrgID":          validation__.Cache.OrgID,
		"OrgName":        validation__.Cache.OrgName,
		"OrgEmail":       validation__.Cache.OrgEmail,
		"OrgRoles":       validation__.Cache.Get_Roles(config.Service.HTTP),
	})
}

func (srv *Manager_Service) handle_http_config(w http.ResponseWriter, r *http.Request) {
	service_fonfigs := srv.Get_Configurations()
	domain, _, _ := net.SplitHostPort(r.Host)
	config := srv.Get_Service_Config(domain)
	page_error := ""

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		if r.FormValue("action") == "edit-http" {
			config.Service.HTTP.Websockets = r.FormValue("ws") == "on"
			config.Service.HTTP.Wildcard = r.FormValue("wc") == "on"
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

		} else if r.FormValue("action") == "toggle-require" {
			for i, location := range config.Service.HTTP.Locations {
				if location.Path == r.FormValue("path") {
					config.Service.HTTP.Locations[i].EnforceMTLS = r.FormValue("require") == "on"
					break
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "toggle-enforce" {
			for i, location := range config.Service.HTTP.Locations {
				if location.Path == r.FormValue("path") {
					config.Service.HTTP.Locations[i].EnforceRoles = r.FormValue("enforce") == "on"
					break
				}
			}

			page_error = srv.update_service_config(domain, config)

		} else if r.FormValue("action") == "toggle-all-roles" {
			for i, location := range config.Service.HTTP.Locations {
				if location.Path == r.FormValue("path") {
					config.Service.HTTP.Locations[i].AllowAllRoles = r.FormValue("all-roles") == "on"
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
		"CurrentPage":    "HTTP Config",
		"SRV_Port":       global.Config__.AdminPort,
		"Local_Endpoint": global.Config__.LocalAuthenticatorEndpoint,
		"DynamicPages":   service_fonfigs,
		"Service":        config.Service,
		"Domain":         srv.Perimeter_APIs[domain].Domain(),
		"App_Port":       global.Config__.ApplicationPort,
		"PageError":      page_error,
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

	srv.managed_services[domain] = &config
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

func (srv *Manager_Service) Start_Openresty() int {
	if srv.openresty != nil {
		log.Printf("Openresty already running. Sending reload signal ...\n")
		if err := srv.openresty.Process.Signal(syscall.SIGHUP); err != nil {
			log.Printf("Error reloading %v ...\n", err)
		}

		return srv.openresty.SysProcAttr.Pgid
	}

	log.Printf("Starting Openresty HTTP/TCP Proxy Server with config: %s", global.Config__.DataDirectory+"/conf/nginx.conf")

	// configure_openresty();
	utils.WriteToFile(global.Config__.DataDirectory+"/conf/nginx.conf", []byte(integrations.Build_Nginx("")))

	// Command to start (replace with your own)
	srv.openresty = exec.Command("/usr/local/openresty/bin/openresty", "-g", "daemon off;", "-c", global.Config__.DataDirectory+"/conf/nginx.conf")
	srv.openresty.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGTERM,
	}

	// Get the output pipe (stdout and stderr)
	stdout, err := srv.openresty.StdoutPipe()
	if err != nil {
		log.Printf("Error getting stdout: %v\n", err)
		return 0
	}
	stderr, err := srv.openresty.StderrPipe()
	if err != nil {
		log.Printf("Error getting stderr: %v\n", err)
		return 0
	}

	// Start the command
	err = srv.openresty.Start()
	if err != nil {
		log.Printf("Error starting command: %v\n", err)
		return 0
	}

	// Copy stdout and stderr to the console
	go io.Copy(utils.Log_Writer, stdout) // Redirect stdout to console
	go io.Copy(utils.Log_Writer, stderr) // Redirect stderr to console

	go func() {
		err := srv.openresty.Wait()
		log.Println("Openresty exited:", err)
		srv.openresty = nil
	}()

	return srv.openresty.SysProcAttr.Pgid
}

func (srv *Manager_Service) Kill_Openresty() {
	if srv.openresty != nil {
		syscall.Kill(-srv.openresty.SysProcAttr.Pgid, syscall.SIGTERM)
	}
}

func (srv *Manager_Service) Get_Service_Config(domain string) integrations.ServiceConfig {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	config := srv.managed_services[domain]

	if config == nil {
		c := load_service_config(domain)
		config = &c
		srv.managed_services[domain] = config
	}

	return *config
}

func load_service_config(domain string) integrations.ServiceConfig {
	if global.Config__.Verbose {
		log.Printf("loading configuration for %s", domain)
	}

	config, err := integrations.Parse_Service_Config(global.Config__.DataDirectory + "/services/" + domain + ".yaml")

	if err != nil {
		log.Printf("No config file for %s, initializing service", domain)
		config = integrations.ServiceConfig{
			Service: integrations.ManagedService{
				Port: global.Config__.ApplicationOperatingPort,
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
					Trusted_Headers: integrations.Trusted_Headers_Auth{
						MtlsOrgID:    "X-mTLS-Org-ID",
						MtlsOrgName:  "X-mTLS-Org-Name",
						MtlsOrgEmail: "X-mTLS-Org-Email",
						MtlsRoles:    "X-mTLS-Roles",
						MtlsLocalID:  "X-mTLS-Local-ID",
					},
					Locations: []integrations.Location{
						integrations.Location{
							Path:           "/",
							EnforceMTLS:    true,
							EnforceRoles:   true,
							AllowAllRoles:  false,
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
