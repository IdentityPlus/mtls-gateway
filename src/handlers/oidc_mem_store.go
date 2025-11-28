package handlers

import (
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type MemoryStore struct {
	sync.Mutex
	data   map[string]*OIDCAuthContext
	keyset *OIDCKeySet
}

func NewMemoryStore() *MemoryStore {
	ephemeral_key_set := NewEphemeralOIDCKeySet()

	store := &MemoryStore{
		data:   make(map[string]*OIDCAuthContext),
		keyset: ephemeral_key_set,
	}

	go store.cleanupLoop()
	return store
}

func (m *MemoryStore) cleanupLoop() {
	for {
		time.Sleep(30 * time.Second)
		now := time.Now()
		m.Lock()
		for k, v := range m.data {
			if v.ExpiresAt.Before(now) {
				delete(m.data, k)
			}
		}
		m.Unlock()
	}
}

func (m *MemoryStore) Put(domain string, ctx *OIDCAuthContext) {
	m.Lock()
	defer m.Unlock()

	m.data[domain+"/"+ctx.Code] = ctx
}

func (m *MemoryStore) Get(domain, code string) *OIDCAuthContext {
	m.Lock()
	defer m.Unlock()

	if ctx, ok := m.data[domain+"/"+code]; ok {
		return ctx
	}

	return nil
}

func (m *MemoryStore) Delete(domain, code string) *OIDCAuthContext {
	m.Lock()
	defer m.Unlock()
	if ctx, ok := m.data[domain+"/"+code]; ok {
		delete(m.data, domain+"/"+ctx.Code)
		return ctx
	}
	return nil
}

func (m *MemoryStore) Issue_Claim(domain string, client_id string, iss string, auth_request OIDCAuthContext, orgID string, email string, name string, groups []string) (OIDCTokenResponse, error) {
	claims := jwt.MapClaims{
		"sub":                auth_request.Mtls_ID,
		"preferred_username": orgID,
		"email":              email,
		"name":               name,
		"groups":             groups,
		"iat":                time.Now().Unix(),
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iss":                iss,
		"nonce":              auth_request.Nonce,
		"aud":                client_id,
		"email_verified":     true,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.keyset.kid
	id_token, _ := token.SignedString(m.keyset.privateKey)

	// ----- Create ACCESS TOKEN as JWT -----
	accessClaims := jwt.MapClaims{
		"sub":    auth_request.Mtls_ID,
		"aud":    client_id,
		"iss":    iss,
		"scope":  "openid profile email",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"groups": groups,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken.Header["kid"] = m.keyset.kid
	signedAccessToken, _ := accessToken.SignedString(m.keyset.privateKey)

	ctx := OIDCAuthContext{
		Code: signedAccessToken,
		// Code:         randomToken(32),
		Mtls_ID:      auth_request.Mtls_ID,
		ExpiresAt:    time.Now().Add(3600 * time.Second), // one hour
		RefreshToken: randomToken(32),
		Claims:       claims,
		Nonce:        auth_request.Nonce,
	}

	m.Put(domain, &ctx)

	return OIDCTokenResponse{
		AccessToken:  signedAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: ctx.RefreshToken,
		IDToken:      id_token,
		Nonce:        ctx.Nonce,
	}, nil
}
