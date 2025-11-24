package integrations

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"identity.plus/mtls-gw/global"
	"identity.plus/mtls-gw/utils"
	// "log"
)

type Nginx_Builder struct {
	MtlsIdDirectory string
	Domain          string
	Service         ManagedService
}

func (cfg Nginx_Builder) domain() string {
	return cfg.Domain
}

func (cfg Nginx_Builder) build_worker(instance string) string {
	return "        server " + instance + ";\n"
}

func (cfg Nginx_Builder) build_upstream() string {

	workers := ""
	for _, i := range cfg.Service.Upstream.Workers {
		workers += cfg.build_worker(i)
	}

	return utils.Build_Template("./webapp/templates/nginx/upstream.conf", map[string]string{
		"{{NAME}}":    "up_" + strings.ReplaceAll(cfg.domain(), ".", "_"),
		"{{WORKERS}}": workers,
	})
}

func (cfg Nginx_Builder) build_tls() string {

	certificate_dir := cfg.MtlsIdDirectory

	if strings.Contains(cfg.Service.Authority, "letsencrypt") && utils.FileExists(global.Config__.DataDirectory+"/letsencrypt/"+cfg.domain()+"/service-id/"+cfg.domain()+".cer") && utils.FileExists(global.Config__.DataDirectory+"/letsencrypt/"+cfg.domain()+"/service-id/"+cfg.domain()+".key") {
		certificate_dir += "/letsencrypt"
	} else {
		certificate_dir += "/identity"
	}

	return utils.Build_Template("./webapp/templates/nginx/tls-config.conf", map[string]string{
		"{{DOMAIN}}":   cfg.domain(),
		"{{ID-DIR}}":   cfg.MtlsIdDirectory,
		"{{CERT-DIR}}": certificate_dir,
	})
}

func (cfg Nginx_Builder) build_custom(location Location) string {
	return "            " + strings.ReplaceAll(location.CustomCommands, "\n", "\n            ")
}

func (cfg Nginx_Builder) build_TCP_lua_access() string {
	if len(cfg.Service.TCP.RolesAllowed) == 0 {
		return ""
	}

	roles := ""
	for _, r := range cfg.Service.TCP.RolesAllowed {
		if len(roles) > 0 {
			roles += ", "
		}

		roles += "'" + r + "'"
	}

	return utils.Build_Template("./webapp/templates/nginx/tcp-access-lua.conf", map[string]string{
		"{{SERVICE}}": cfg.domain(),
		"{{ROLES}}":   roles,
	})
}

func (cfg Nginx_Builder) build_HTTP_lua_access(location Location) string {
	enforcement := ""

	// there is no enforcement for application mode
	if cfg.Service.HTTP.AccessMode != "Application" {
		enforcement = cfg.build_HTTP_access_mode_gw(location)
	}

	return utils.Build_Template("./webapp/templates/nginx/http-access-lua.conf", map[string]string{
		"{{ID}}":          cfg.Service.HTTP.MtlsID,
		"{{ENFORCEMENT}}": enforcement,
	})
}

func (cfg Nginx_Builder) build_HTTP_access_mode_gw(location Location) string {
	if !location.EnforceMTLS {
		return ""
	}

	mtls_headers := ""
	// populate the mtLS headers for both Gateway and Proxy mode but skip for OIDC
	if cfg.Service.HTTP.AccessMode != "OIDC" {
		mtls_headers = "'" + cfg.Service.HTTP.MtlsAgent + "', " + "'" + cfg.Service.HTTP.Trusted_Headers.MtlsOrgID + "', " + "'" + cfg.Service.HTTP.Trusted_Headers.MtlsOrgName + "', " + "'" + cfg.Service.HTTP.Trusted_Headers.MtlsOrgEmail + "', " + "'" + cfg.Service.HTTP.Trusted_Headers.MtlsRoles + "', " + "'" + cfg.Service.HTTP.Trusted_Headers.MtlsLocalID + "'"
		mtls_headers = "                identityplus.populate_mtls_headers(validation, " + mtls_headers + ")"
	}

	roles := ""
	if !location.AllowAllRoles {
		for _, r := range location.RolesAllowed {
			if len(roles) > 0 {
				roles += ", "
			}

			roles += "'" + r + "'"
		}
	}

	template := ""
	if !location.EnforceRoles {
		template = "http-access-lua-gw-ignore-roles"
	} else if location.AllowAllRoles {
		template = "http-access-lua-gw-any-role"
	} else {
		template = "http-access-lua-gw-these-roles"
	}

	return utils.Build_Template("./webapp/templates/nginx/"+template+".conf", map[string]string{
		"{{SERVICE}}": cfg.domain(),
		"{{HEADERS}}": mtls_headers,
		"{{ROLES}}":   roles,
	})
}

func (cfg Nginx_Builder) build_HTTP_defaults() string {
	real_ip := cfg.Service.HTTP.XRealIP
	forward_ip := cfg.Service.HTTP.XForwardedFor
	forward_proto := cfg.Service.HTTP.XForwardedProto
	host_header := "$host"

	if cfg.Service.HTTP.HostHeader != "" {
		host_header = cfg.Service.HTTP.HostHeader
	}

	return utils.Build_Template("./webapp/templates/nginx/http-defaults.conf", map[string]string{
		"{{X-Forwarded-For}}":   forward_ip,
		"{{X-Forwarded-Proto}}": forward_proto,
		"{{X-Real-IP}}":         real_ip,
		"{{HOST-HEADER}}":       host_header,
	})
}

func (cfg Nginx_Builder) build_web_sockets() string {

	if !cfg.Service.HTTP.Websockets {
		return ""
	}

	return utils.Build_Template("./webapp/templates/nginx/web-sockets.conf", map[string]string{})
}

func (cfg Nginx_Builder) build_HTTP_locations() string {

	locations := ""

	for _, location := range cfg.Service.HTTP.Locations {

		http_access := cfg.build_HTTP_lua_access(location)
		http_proxy := ""
		http_defaults := cfg.build_HTTP_defaults()
		websockets := cfg.build_web_sockets()
		custom := cfg.build_custom(location)

		if !strings.Contains(custom, "proxy_pass ") {
			http_proxy = "\n            proxy_pass http://up_" + strings.ReplaceAll(cfg.domain(), ".", "_") + ";"
		}

		location := utils.Build_Template("./webapp/templates/nginx/location.conf", map[string]string{
			"{{PATH}}":          location.Path,
			"{{LUA_ACCESS}}":    http_access,
			"{{CUSTOM}}":        custom,
			"{{HTTP-DEFAULTS}}": http_defaults,
			"{{WEBSOCKETS}}":    websockets,
			"{{UPSTREAM}}":      http_proxy,
		})

		locations += location
	}

	var location = ""
	if cfg.Service.HTTP.AccessMode == "OIDC" {
		oidc_ep := Location{
			Path:          "/mtls-gw/oidc/",
			EnforceMTLS:   true,
			EnforceRoles:  false,
			AllowAllRoles: true,
		}

		location = utils.Build_Template("./webapp/templates/nginx/location.conf", map[string]string{
			"{{PATH}}":          oidc_ep.Path,
			"{{LUA_ACCESS}}":    cfg.build_HTTP_lua_access(oidc_ep),
			"{{CUSTOM}}":        "",
			"{{HTTP-DEFAULTS}}": cfg.build_HTTP_defaults(),
			"{{WEBSOCKETS}}":    "",
			"{{UPSTREAM}}":      "\n            proxy_pass http://" + global.Config__.LocalAuthenticatorEndpoint + ";",
		})

	} else {
		location = utils.Build_Template("./webapp/templates/nginx/location.conf", map[string]string{
			"{{PATH}}":          "/mtls-gw/oidc/",
			"{{LUA_ACCESS}}":    "",
			"{{CUSTOM}}":        "            default_type text/plain;",
			"{{HTTP-DEFAULTS}}": "",
			"{{WEBSOCKETS}}":    "",
			"{{UPSTREAM}}":      "            return 404 \"OpenID-Connect authentication not enabled for this service.\\n\";",
		})
	}

	locations += location

	// log.Printf("/n---------------------/n%s/n--------------/n", locations)

	return locations
}

func Build_Nginx(environment string) string {
	pwd, _ := os.Getwd()
	return utils.Build_Template("./webapp/templates/nginx/nginx.conf", map[string]string{
		"{{PWD}}":    pwd,
		"{{ID-DIR}}": global.Config__.DataDirectory + environment,
	})
}

func (cfg Nginx_Builder) Build() string {
	tcp_access := ""
	tcp_proxy := ""
	http_locations := ""
	server_name := ""

	if cfg.Service.Mode == "TCP" {
		server_name = "        ssl_preread                 on;\n"
		tcp_access = cfg.build_TCP_lua_access()
		if tcp_access != "" {
			tcp_proxy = "\n        proxy_pass up_" + strings.ReplaceAll(cfg.domain(), ".", "_") + ";"
		}
	} else if cfg.Service.Mode == "HTTP" {
		http_locations = cfg.build_HTTP_locations()
		server_name = "        server_name                 "
		if cfg.Service.HTTP.Wildcard {
			server_name += "*."
		}
		server_name += cfg.domain() + ";\n"
	}

	return utils.Build_Template("./webapp/templates/nginx/server.conf", map[string]string{
		"{{UPSTREAM}}":       cfg.build_upstream(),
		"{{PORT}}":           strconv.Itoa(cfg.Service.Port),
		"{{SNI}}":            server_name,
		"{{TLS}}":            cfg.build_tls(),
		"{{ID-DIR}}":         cfg.MtlsIdDirectory,
		"{{TCP-ACCESS}}":     tcp_access,
		"{{TCP-BACK-END}}":   tcp_proxy,
		"{{HTTP-LOCATIONS}}": http_locations,
	})
}

func (cfg Nginx_Builder) Openresty_Test_Config(config_file string) string {

	cmd := exec.Command("/usr/local/openresty/bin/openresty", "-t", "-c", config_file)

	// Buffer to capture the command's output
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Run the command
	err := cmd.Run()
	if err != nil {
		// log.Println("Error running command:", err)
	}

	// Convert output to string and check if it contains "test is successful"
	output := out.String()
	if strings.Contains(output, "test is successful") {
		return ""
	} else {
		return fmt.Sprintf("%s", output)
	}
}
