package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type OIDCAuthContext struct {
	Code         string
	RedirectURI  string
	Mtls_ID      string
	RefreshToken string
	Claims       jwt.MapClaims
	ExpiresAt    time.Time
	Nonce        string
}

type OIDCKeySet struct {
	mu         sync.Mutex
	privateKey *rsa.PrivateKey
	publicJWK  map[string]interface{}
	kid        string
}

// OIDC token response
type OIDCTokenResponse struct {
	Reference    string
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Nonce        string `json:"nonce"`
}

func (ks *OIDCKeySet) Generate() {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Generate a 2048-bit RSA keypair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

	// Build JWK fields (public only)
	nBytes := key.PublicKey.N.Bytes()
	eBytes := big.NewInt(int64(key.PublicKey.E)).Bytes()

	ks.kid = randomToken(16)
	ks.privateKey = key
	ks.publicJWK = map[string]interface{}{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
		"kid": ks.kid,
	}
}

func NewEphemeralOIDCKeySet() *OIDCKeySet {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := privateKey.PublicKey

	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	kid := "ephemeral-1"

	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   n,
		"e":   e,
	}

	return &OIDCKeySet{
		privateKey: privateKey,
		publicJWK:  jwk,
		kid:        kid,
	}
}
