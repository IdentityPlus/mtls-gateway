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

	return utils.Build_Template("./webapp/templates/nginx/tls-config.conf", map[string]string{
		"{{DOMAIN}}": cfg.domain(),
		"{{ID-DIR}}": cfg.MtlsIdDirectory,
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
	if location.Bypass {
		return ""
	}

	roles := ""
	for _, r := range location.RolesAllowed {
		if len(roles) > 0 {
			roles += ", "
		}

		roles += "'" + r + "'"
	}

	no_rules := ""
	no_headers := ""

	if cfg.Service.HTTP.AccessMode != "Gateway" {
		no_rules = "-- "
	}

	if cfg.Service.HTTP.AccessMode == "Application" {
		no_headers = "-- "
		no_rules = "-- "
	}

	return utils.Build_Template("./webapp/templates/nginx/http-access-lua.conf", map[string]string{
		"{{SERVICE}}":    cfg.domain(),
		"{{ROLES}}":      roles,
		"{{ID}}":         cfg.Service.HTTP.MtlsID,
		"{{HEADERS}}":    "'" + cfg.Service.HTTP.MtlsAgent + "', " + "'" + cfg.Service.HTTP.MtlsOrgID + "', " + "'" + cfg.Service.HTTP.MtlsOrgName + "', " + "'" + cfg.Service.HTTP.MtlsOrgEmail + "', " + "'" + cfg.Service.HTTP.MtlsRoles + "', " + "'" + cfg.Service.HTTP.MtlsLocalID + "'",
		"{{NO-RULES}}":   no_rules,
		"{{NO-HEADERS}}": no_headers,
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
		// fmt.Println("Error running command:", err)
	}

	// Convert output to string and check if it contains "test is successful"
	output := out.String()
	if strings.Contains(output, "test is successful") {
		return ""
	} else {
		return fmt.Sprintf("%s", output)
	}
}
