package global

import(
	"time"
)

// Struct to hold the TLS configuration parameters from the YAML file
type Config struct {
	AdminPort	             string     `yaml:"admin_port"`
	AdminAccessPort	         string     `yaml:"admin_access_port"`
	ValidationServicePort    string     `yaml:"validation_service_port"`
	DataDirectory            string     `yaml:"data_directory"`
	MtlsIdTtl	             int        `yaml:"mtls_id_ttl"`
	DeviceName               string     `yaml:"device_name"`
	RolesAllowed             []string   `yaml:"roles_allowed"`
	IdentityBroker           string     `yaml:"identity_broker"`
	Verbose                  bool       `yaml:"verbose"`
}
var Config__ *Config

type Stats struct {
	LaunchTime           time.Time
}
var Stats__ = Stats{}
