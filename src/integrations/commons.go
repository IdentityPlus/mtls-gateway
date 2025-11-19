package integrations

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v2"
	"identity.plus/mtls-gw/global"
	// "strings"
	// "mtls-gw/global"
)

type Location struct {
	Path           string   `yaml:"path"`
	EnforceMTLS    bool     `yaml:"enforce-mtls"`
	EnforceRoles   bool     `yaml:"enforce-roles"`
	AllowAllRoles  bool     `yaml:"allow-all-roles"`
	RolesAllowed   []string `yaml:"roles-allowed"`
	CustomCommands string   `yaml:"custom-commands"`
}

type Tcp struct {
	RolesAllowed []string `yaml:"roles-allowed"`
}

type OIDC_Client struct {
	Id     string `yaml:"id"`
	Secret string `yaml:"secret"`
}

type Role_Mapping struct {
	Canonical string `yaml:"canonical"`
	Local     string `yaml:"local"`
}

type OIDC_Auth struct {
	Clients []OIDC_Client `yaml:"clients"`
}

type Role_Translator struct {
	Mappings          []Role_Mapping `yaml:"mappings"`
	Remove_Org_Prefix bool           `yaml:"remove-org-prefix"`
}

type Trusted_Headers_Auth struct {
	MtlsOrgID    string `yaml:"mtls-org-id"`
	MtlsOrgName  string `yaml:"mtls-org-name"`
	MtlsOrgEmail string `yaml:"mtls-org-email"`
	MtlsRoles    string `yaml:"mtls-roles"`
	MtlsLocalID  string `yaml:"mtls-local-id"`
}

type Http struct {
	AccessMode      string               `yaml:"access-mode"` // Gateway, Application, Proxy, OIDC
	Translator      Role_Translator      `yaml:"translator"`
	OIDC            OIDC_Auth            `yaml:"oicd-config"`
	Trusted_Headers Trusted_Headers_Auth `yaml:"trusted-headers"`
	Websockets      bool                 `yaml:"websockets"`
	Wildcard        bool                 `yaml:"wildcard"`
	HostHeader      string               `yaml:"host-header"`
	XForwardedFor   string               `yaml:"x-forwarded-for"`
	XForwardedProto string               `yaml:"x-forwarded-proto"`
	XRealIP         string               `yaml:"x-real-ip"`
	MtlsID          string               `yaml:"mtls-id"`
	MtlsAgent       string               `yaml:"mtls-agent"`
	Locations       []Location           `yaml:"locations"`
}

type Upstream struct {
	Workers []string `yaml:"workers"`
}

type ManagedService struct {
	Port     int      `yaml:"port"`
	Mode     string   `yaml:"mode"`
	Upstream Upstream `yaml:"upstream"`
	TCP      Tcp      `yaml:"tcp"`
	HTTP     Http     `yaml:"http"`
}

type ServiceConfig struct {
	Service ManagedService `yaml:"managed-service"`
}

func Parse_Service_Config(service_file string) (ServiceConfig, error) {
	var config ServiceConfig
	yamlData, err := os.ReadFile(service_file)

	if err != nil {
		return config, err
	}

	// log.Println("----- reading -------\n" + string(yamlData) + "\n------------------")

	err = yaml.Unmarshal([]byte(yamlData), &config)
	if err != nil {
		return config, err
	}

	return config, nil

}

func Write_Service_Config(serviceFile string, config ServiceConfig) error {
	// Marshal the struct into YAML format
	yamlData, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("error marshaling YAML: %w", err)
	}

	// log.Println("------ writing ------\n" + string(yamlData) + "\n------------------")

	// Write the YAML data to the specified file
	os.Mkdir(global.Config__.DataDirectory+"/services/", os.FileMode(os.O_RDWR))
	err = os.WriteFile(serviceFile, yamlData, 0644)
	if err != nil {
		log.Printf("unable to write to service config file: %v", err)
		return fmt.Errorf("unable to write to service config file: %w", err)
	}

	log.Printf("Service configuration saved successfully to %s\n", serviceFile)
	return nil
}
