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
		log.Fatalf("Unable to read config file: %v", err)
	}

	// Parse the YAML file into the TLSConfig struct
	if err := yaml.Unmarshal(fileData, &config); err != nil {
		log.Fatalf("Unable to parse config file: %v", err)
	}

	if config.Log_Retention == 0 {
		config.Log_Retention = 12
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
