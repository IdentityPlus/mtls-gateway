package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"identity.plus/mtls-gw/global"
	"identity.plus/mtls-gw/integrations"
)

var oicd_mem_store = NewMemoryStore()

type OIDC_Authenticator struct {
	domain  string
	service integrations.ManagedService
}

func NewOIDC_Authenticator(domain__ string, service__ integrations.ManagedService) *OIDC_Authenticator {

	authenticator := &OIDC_Authenticator{
		domain:  domain__,
		service: service__,
	}

	return authenticator
}

/**
 * Start the OIDC authorization process
 */
func (auth *OIDC_Authenticator) handle_oidc_authorization(w http.ResponseWriter, r *http.Request) {
	err := pre_process_request(r, false)
	if err != nil {
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Authenticacte OIDC Client
	code := r.Form.Get("code")
	authenticated := false
	oidcClientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	for _, c := range auth.service.HTTP.OIDC.Clients {
		if oidcClientID == c.Id && clientSecret == c.Secret {
			authenticated = true
			break
		}
	}

	if !authenticated || code == "" {
		log.Printf("Missing parameter, oidcClient=%s, secret=*****, code=%s", oidcClientID, code)
		http.Error(w, "missing oidc client identity parameters", http.StatusBadRequest)
		return
	}

	authReq := oicd_mem_store.Get(auth.domain, code)
	if authReq == nil {
		log.Printf("Invalid or expired code: client_id=%s, code=%s", oidcClientID, code)
		http.Error(w, "invalid or expired code", http.StatusBadRequest)
		return
	}

	u, err := url.Parse(r.Form.Get("redirect_uri"))
	if err != nil {
		panic(err)
	}

	target_service := u.Hostname()

	api := Manager_Service__.Perimeter_APIs[target_service]

	if api == nil {
		log.Printf("Erro: no API for target service %s", target_service)
	}

	validation, _ := api.Validate_Client_Identity_SN(authReq.Mtls_ID, target_service, true)

	// Generate tokens
	resp, _ := oicd_mem_store.Issue_Claim(
		auth.domain,
		oidcClientID,
		"http://"+global.Config__.LocalAuthenticatorEndpoint+"/mtls-gw/oidc/"+auth.domain,
		*authReq,
		validation.Cache.OrgID,
		validation.Cache.OrgEmail,
		validation.Cache.OrgName,
		validation.Cache.Get_Roles(auth.service.HTTP),
	)

	// json_resp, _ := json.Marshal(resp)
	// log.Printf("- >>> responding: %s", string(json_resp))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

/**
 * Start the OIDC authentication process
 */
func (auth *OIDC_Authenticator) handle_OAuth2_login(w http.ResponseWriter, r *http.Request) {

	err := pre_process_request(r, false)
	if err != nil {
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Extract the client certificate. We can rely on this header as it is not user modifiable for standardization
	// we will get the user info from cache based on this.
	mtls_id := r.Header.Get("X-TLS-Client-Serial")
	if mtls_id == "" {
		log.Printf("Error: missing client certifficate.")
		http.Error(w, "missing client certificate", http.StatusUnauthorized)
		return
	}

	// Authenticacte OIDC Client
	registered := false
	oidcClientID := r.Form.Get("client_id")
	for _, c := range auth.service.HTTP.OIDC.Clients {
		if oidcClientID == c.Id {
			registered = true
			break
		}
	}

	if !registered {
		log.Printf("Missing parameter, oidcClient=%s, secret=*****", oidcClientID)
		http.Error(w, "missing oidc client identity parameters", http.StatusBadRequest)
		return
	}

	responseType := r.FormValue("response_type")
	if responseType != "code" {
		log.Printf("Error: response_type != 'code'")
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	// We are not going to validate the client ID as
	redirectURI := r.FormValue("redirect_uri")
	// scope := r.FormValue("scope") // we don't care about the scope at this point
	state := r.FormValue("state")

	nonce := r.FormValue("nonce")
	if nonce == "" {
		nonce = randomToken(24)
	}

	code := randomToken(24)
	ctx := &OIDCAuthContext{
		Code:        code,
		Mtls_ID:     mtls_id,
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(60 * time.Second),
		Nonce:       nonce,
	}

	oicd_mem_store.Put(auth.domain, ctx)

	// Redirect to callback with code and state
	redirect := redirectURI + "?code=" + code
	if state != "" {
		redirect += "&state=" + state
	}

	http.Redirect(w, r, redirect, http.StatusFound)
}

func (auth *OIDC_Authenticator) oidc_configuration_endpoint() string {
	return "http://" + global.Config__.LocalAuthenticatorEndpoint + "/mtls-gw/oidc/" + auth.domain + "/.well-known/openid-configuration"
}

// handle_oidc_configuration returns a handler that serves the OIDC discovery document
func (auth *OIDC_Authenticator) handle_oidc_configuration(w http.ResponseWriter, r *http.Request) {
	err := pre_process_request(r, false)
	if err != nil {
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// The base issuer URL should not end with a slash
	auth_port := ""
	if global.Config__.ApplicationPort != 443 {
		auth_port = ":" + strconv.Itoa(global.Config__.ApplicationPort)
	}

	config := map[string]interface{}{
		"issuer":                                "http://" + global.Config__.LocalAuthenticatorEndpoint + "/mtls-gw/oidc/" + auth.domain,
		"authorization_endpoint":                "https://" + auth.domain + auth_port + "/mtls-gw/oidc/auth",
		"token_endpoint":                        "http://" + global.Config__.LocalAuthenticatorEndpoint + "/mtls-gw/oidc/" + auth.domain + "/token",
		"userinfo_endpoint":                     "http://" + global.Config__.LocalAuthenticatorEndpoint + "/mtls-gw/oidc/" + auth.domain + "/userinfo",
		"jwks_uri":                              "http://" + global.Config__.LocalAuthenticatorEndpoint + "/mtls-gw/oidc/" + auth.domain + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"claims_supported":                      []string{"sub", "email", "name", "preferred_username", "groups"},
		"code_challenge_methods_supported":      []string{"S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(config)
}

func (auth *OIDC_Authenticator) handle_oidc_jwks(w http.ResponseWriter, r *http.Request) {
	err := pre_process_request(r, false)
	if err != nil {
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	oicd_mem_store.keyset.mu.Lock()
	defer oicd_mem_store.keyset.mu.Unlock()

	jwks := map[string]interface{}{
		"keys": []interface{}{oicd_mem_store.keyset.publicJWK},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(jwks)
}

func (auth *OIDC_Authenticator) handle_oidc_user_info(w http.ResponseWriter, r *http.Request) {
	err := pre_process_request(r, false)
	if err != nil {
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	authReq := oicd_mem_store.Get(auth.domain, tokenString)
	if authReq == nil {
		log.Printf("Invalid or expired bearer token: %s", tokenString)
		http.Error(w, "invalid or expired bearer token", http.StatusBadRequest)
		return
	}

	// Extract user claims
	claims := authReq.Claims
	if claims == nil {
		log.Printf("[userinfo] No claims found for token: %s", tokenString)
		http.Error(w, "no user info available", http.StatusInternalServerError)
		return
	}

	// Prepare userinfo response per OIDC spec
	userInfo := map[string]interface{}{
		"sub":                claims["sub"],
		"preferred_username": claims["preferred_username"],
		"name":               claims["name"],
		"groups":             claims["groups"],
		"email":              claims["email"],
		"email_verified":     claims["email_verified"],
	}

	// json_resp, _ := json.Marshal(userInfo)
	// log.Printf("- >>> responding: %s", string(json_resp))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		log.Printf("[userinfo] Failed to encode response: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
