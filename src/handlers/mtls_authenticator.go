package handlers

import (
	"net/http"
)

/**
 * Use the mTLS Perimeter API to call Identity Plus and validate the client certificate based on the id
 */
func handle_mtls_id_validation(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodPost {
		// log.Printf("validating: %s", r.URL)
		// subject := r.URL.Path[len("/mtls-gw/validate/"):]

		mtls_id := r.Header["X-Tls-Client-Serial"][0]
		target_service := r.Header["X-Requesting-Service"][0]

		// if strings.LastIndex(subject, "/") != -1 {
		// 	mtls_id = subject[strings.LastIndex(subject, "/")+1:]
		// 	target_service = subject[:strings.LastIndex(subject, "/")]
		// } else {
		// 	mtls_id = subject
		// }

		// log.Printf("validating: %s at %s", mtls_id, target_service)

		api := Manager_Service__.Perimeter_APIs[target_service]

		// log.Printf("Remote IP: %s, Client SN: %s @ %s\n", r.Header["Remote-Ip"][0], mtls_id, target_service)

		if api != nil {
			validation, err := api.Validate_Client_Identity_SN(mtls_id, "", true)

			if err == "" {
				w.Write(validation.Raw)
			} else {
				http.Error(w, err, 500)
			}
		} else {
			w.Write([]byte("{\"Simple-Response\":{\"message\":\"No such service: " + target_service + "\",\"outcome\":\"ER 0000 Undetermined error\"}}"))
		}

	} else {
		http.Error(w, "unsupported method: "+r.Method, http.StatusForbidden)
	}
}
