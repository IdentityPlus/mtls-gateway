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

	err := os.MkdirAll("/var/mtls-gateway/logs", 0755)
	if err != nil {
		log.Printf("Unable to create log directory: %s", err)
		return
	}

	config_file := "/etc/mtls-gateway/config.yaml"
	if len(os.Args) > 1 {
		config_file = os.Args[1]
	}

	utils.Log_Writer, _ = utils.NewDailyRotatingWriter("/var/mtls-gateway/logs")
	log.SetOutput(utils.Log_Writer)

	global.Load_Config(config_file)
	local_ip, _ := utils.Get_Local_Private_IP()
	log.Printf("Local Private IP Address is: %s\n", local_ip)
	if strings.HasPrefix(global.Config__.LocalAuthenticatorEndpoint, "$") {
		global.Config__.LocalAuthenticatorEndpoint = local_ip + global.Config__.LocalAuthenticatorEndpoint[len("$PRIVATE_IP"):]
		global.Config__.Save(config_file)
	}

	go utils.Log_Writer.Log_Eraser_Process()

	identities := handlers.Manager_Service__.Get_Configurations()
	initialized := false

	for _, id_dir := range identities {
		handlers.Manager_Service__.Configure_Perimeter_API(id_dir)
		initialized = true
	}

	// run a certificate update in synch
	update_certificates()

	if initialized {
		go handlers.Manager_Service__.Start()
	} else {
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
