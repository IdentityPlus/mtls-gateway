package global

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"
)

// Struct to hold the TLS configuration parameters from the YAML file
type Config struct {
	Theme                      string   `yaml:"theme"`
	AdminOperatingPort         int      `yaml:"admin_operating_port"`
	ApplicationPort            int      `yaml:"application_port"`
	ApplicationOperatingPort   int      `yaml:"application_operating_port"`
	AdminPort                  int      `yaml:"admin_port"`
	LocalAuthenticatorEndpoint string   `yaml:"local_authenticator_endpoint"`
	AuthenticatorOperatingPort int      `yaml:"authenticator_operating_port"`
	Log_Retention              int      `yaml:"log_retention"`
	DataDirectory              string   `yaml:"data_directory"`
	MtlsIdTtl                  int      `yaml:"mtls_id_ttl"`
	DeviceName                 string   `yaml:"device_name"`
	RolesAllowed               []string `yaml:"roles_allowed"`
	IdentityBroker             string   `yaml:"identity_broker"`
	Verbose                    bool     `yaml:"verbose"`
}

var Config__ *Config
var Intialized = false

type Stats struct {
	LaunchTime time.Time
}

var Stats__ = Stats{}

func Load_Config(config_file string) {
	log.Printf("Loading configuration: %s\n", config_file)
	var config Config

	// Read the TLS configuration file
	fileData, err := os.ReadFile(config_file)

	if err != nil {
		log.Printf("Unable to read config file: %v, using default", err)

	} else if err := yaml.Unmarshal(fileData, &config); err != nil {
		// Parse the YAML file into the TLSConfig struct
		log.Printf("Unable to parse config file: %v, using default", err)
	}

	if config.AdminOperatingPort == 0 {
		config.Log_Retention = 12
		config.AdminPort = 444
		config.AdminOperatingPort = 444
		config.ApplicationOperatingPort = 443
		config.ApplicationPort = 443
		config.AuthenticatorOperatingPort = 81
		config.LocalAuthenticatorEndpoint = "$PRIVATE_IP:81"
		config.DataDirectory = "/var/mtls-gateway"
		config.MtlsIdTtl = 5
		config.DeviceName = "Mtls-Gateway"
		config.IdentityBroker = "identity.plus"
		config.RolesAllowed = []string{"org. administrator", "org. manager", "administrator", "manager"}
	}

	Config__ = &config
}

func (cfg *Config) Save(path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
