package integrations

import (
	"fmt"
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v2"
	// "strings"
	// "mtls-gw/global"
)

type Location struct {
	Path           string   `yaml:"path"`
	Bypass         bool     `yaml:"bypass"`
	RolesAllowed   []string `yaml:"roles-allowed"`
	CustomCommands string   `yaml:"custom-commands"`
}

type Tcp struct {
	RolesAllowed []string `yaml:"roles-allowed"`
}

type Http struct {
	AccessMode      string     `yaml:"split-mode"`
	Websockets      bool       `yaml:"websockets"`
	Wildcard        bool       `yaml:"wildcard"`
	HostHeader      string     `yaml:"host-header"`
	XForwardedFor   string     `yaml:"x-forwarded-for"`
	XForwardedProto string     `yaml:"x-forwarded-proto"`
	XRealIP         string     `yaml:"x-real-ip"`
	MtlsID          string     `yaml:"mtls-id"`
	MtlsAgent       string     `yaml:"mtls-agent"`
	MtlsOrgID       string     `yaml:"mtls-org-id"`
	MtlsRoles       string     `yaml:"mtls-roles"`
	MtlsLocalID     string     `yaml:"mtls-local-id"`
	Locations       []Location `yaml:"locations"`
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
	yamlData, err := ioutil.ReadFile(service_file)

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
	err = ioutil.WriteFile(serviceFile, yamlData, 0644)
	if err != nil {
		return fmt.Errorf("unable to write to service config file: %w", err)
	}

	log.Printf("Service configuration saved successfully to %s\n", serviceFile)
	return nil
}

/*
func Build_Service (config ServiceConfig) string {
	return Build_Nginx_Service(config.Service)
}
*/
