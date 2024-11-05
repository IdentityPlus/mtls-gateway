package main

import (
	"identity.plus/mtls-gw/handlers"

	"time"

	"gopkg.in/yaml.v2"

	// "fmt"
	"log"
	// "io"
	"io/ioutil"
	"os"

	"identity.plus/mtls-gw/global"
	//"mtls-gw/utils"
	// "mtls-gw/mtlsid"
	// "strings"
	//"path/filepath"
)

func load_config(config_file string) {
	log.Println("Loading configuration: %s", config_file)
	var config global.Config

	// Read the TLS configuration file
	fileData, err := ioutil.ReadFile(config_file)
	if err != nil {
		log.Fatalf("Unable to read config file: %v", err)
	}

	// Log the raw file contents to check if it's being read correctly
	// fmt.Println("Raw YAML file data:")
	// fmt.Println(string(fileData))

	// Parse the YAML file into the TLSConfig struct
	if err := yaml.Unmarshal(fileData, &config); err != nil {
		log.Fatalf("Unable to parse config file: %v", err)
	}

	// Print the unmarshalled struct
	// fmt.Printf("Unmarshalled Config: %+v\n", config)

	global.Config__ = &config
}

func update_certificates() bool {
	restart_openresty := false

	for key, perimeter_api := range handlers.Manager_Service__.Perimeter_APIs {
		log.Printf("Updating agent certificate for %s: %s", key, perimeter_api.Self_Authority.Renew(true))

		ans := perimeter_api.Self_Authority.Issue_service_identity(false)
		log.Printf("Updating server certificate for %s: %s", key, ans)

		if ans == "renewed" {
			restart_openresty = true
		}
	}

	currentTime := time.Now()
	handlers.Manager_Service__.Updated = currentTime.Format("2006-01-02 15:04:05")

	return restart_openresty
}

func certificate_update_service() {
	log.Printf("Starting certificate update service ...")

	for {
		// We start by sleeping for a day, because we run an update in synch at startup
		time.Sleep(24 * time.Hour)

		if update_certificates() {
			handlers.Manager_Service__.Start_Openresty()
		}
	}
}

func main() {
	config_file := "./config.yaml"
	if len(os.Args) > 1 {
		config_file = os.Args[1]
	}

	load_config(config_file)

	identities, _ := handlers.List_Service_Configurations()
	initialized := false

	for _, id_dir := range identities {
		handlers.Manager_Service__.Register(id_dir)
		initialized = true
	}

	// run a certificate update in synch
	update_certificates()

	if initialized {
		go handlers.Manager_Service__.Start()
	} else {
		go handlers.Initialization_Service__.Start()
	}

	go handlers.Validation_Service__.Start()
	go handlers.Manager_Service__.Start_Openresty()

	certificate_update_service()
}
