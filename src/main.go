package main

import (
	"log"
	"os"
	"strings"
	"time"

	"identity.plus/mtls-gw/global"
	"identity.plus/mtls-gw/handlers"
	"identity.plus/mtls-gw/utils"
)

func update_certificates() bool {
	restart_openresty := false

	// update Identity Plus Gateway mTLS ID (Client Certificate) and Service IDs (Server Certificates)
	for key, perimeter_api := range handlers.Manager_Service__.Perimeter_APIs {
		log.Printf("Updating agent certificate for %s: %s", key, perimeter_api.Self_Authority.Renew(true))

		ans := perimeter_api.Self_Authority.Issue_service_identity(false)
		log.Printf("Updating server certificate for %s: %s", key, ans)

		if ans == "renewed" {
			restart_openresty = true
		}
	}

	// update Let's Encrypt Server Certificates
	for _, domain := range handlers.Manager_Service__.Get_Configurations() {

		config := handlers.Manager_Service__.Get_Service_Config(domain)
		if strings.Contains(config.Service.Authority, "letsencrypt") {
			result := utils.Issue_Lets_Encrypt_Cert(domain, config.Service.Authority == "letsenecrypt-staging", false, false)

			if result == "renewed" {
				restart_openresty = true
			}
		}
	}

	currentTime := time.Now()
	handlers.Manager_Service__.Updated = currentTime.Format("2006-01-02 15:04:05")

	return restart_openresty
}

func certificate_update_service() {
	log.Printf("Starting certificate update service ...")

	// sleep one minute to allow for system boot
	time.Sleep(1 * time.Minute)

	for {

		if update_certificates() {
			handlers.Manager_Service__.Start_Openresty()
		}

		// sleep half a day - Let's Encrypt recommends twice a day update attempt
		time.Sleep(12 * time.Hour)
	}
}

func main() {

	config_file := "/etc/mtls-gateway/config.yaml"
	if len(os.Args) > 1 {
		config_file = os.Args[1]
	}

	global.Load_Config(config_file)

	err := os.MkdirAll(global.Config__.DataDirectory+"/logs", 0755)
	if err != nil {
		log.Printf("Unable to create log directory: %s", err)
		return
	}

	utils.Log_Writer, _ = utils.NewDailyRotatingWriter(global.Config__.DataDirectory + "/logs")
	log.SetOutput(utils.Log_Writer)

	log.Printf("-----------------------------------------------------------------\n")
	log.Printf("Gateway starting...\n")
	log.Printf("Configuration file: /etc/mtls-gateway/config.yaml")
	log.Printf("Working directory:%s\n", global.Config__.DataDirectory)
	log.Printf("Logging directory:%s/logs\n", global.Config__.DataDirectory)
	local_ip, _ := utils.Get_Local_Private_IP()
	log.Printf("Local Private IP Address is: %s\n", local_ip)
	if strings.HasPrefix(global.Config__.LocalAuthenticatorEndpoint, "$") {
		global.Config__.LocalAuthenticatorEndpoint = local_ip + global.Config__.LocalAuthenticatorEndpoint[len("$PRIVATE_IP"):]
		global.Config__.Save(config_file)
	}

	go utils.Log_Writer.Log_Eraser_Process()

	identities := handlers.Manager_Service__.Get_Configurations()

	for _, id_dir := range identities {
		handlers.Manager_Service__.Configure_Perimeter_API(id_dir)
		global.Intialized = true
	}

	if global.Intialized {
		go handlers.Manager_Service__.Start()
	}

	go handlers.Initialization_Service__.Start()
	go handlers.Validation_Service__.Start()

	handlers.Manager_Service__.Start_Openresty()

	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic: %v", r)
			handlers.Manager_Service__.Kill_Openresty()
		}
	}()

	certificate_update_service()
}
