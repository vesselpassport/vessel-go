package vessel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

func GetWeb3UserContext(req *http.Request) (*Web3UserSession, error) {

	// Assume no token is present by default - standard web2.0 callers
	authToken := ""

	// Extract the web3 auth token from the web3auth cookie value if present
	authCookie, err := req.Cookie("web3auth")
	if err == nil && authCookie != nil {
		authToken = authCookie.Value
	}

	// Token Check - notify user they are missing the web3 login extension if needed
	if authToken == "" {
		return nil, fmt.Errorf("no web3 session token present")
	}

	// Sanity check that we have at least 1 configured permitted scope otherwise warn the user
	if len(gPermittedScopes) == 0 {
		return nil, fmt.Errorf("no permitted scopes are configured - use vessel.AddPermittedScope() to allow at least one server name")
	}

	// Check this token against all configured servername scopes
	for _, required_scope := range gPermittedScopes {

		// Parse the web3 user ID token from the request - This function will only return a populated token parse if its valid
		// otherwise err will be populated with the validation failure information
		t, err := ParseWeb3Token(required_scope, authToken)
		if err != nil {
			continue
		}

		// Load username attestation if present
		username := GetAttestation(req, t.UserID, "web3_name")
		if len(username) > 0 {
			t.Attestations["name"] = username
		}

		// Load verified email attestation if present
		verifiedEmail := GetAttestation(req, t.UserID, "web3_email")
		if len(verifiedEmail) > 0 {
			t.Attestations["email"] = verifiedEmail
		}

		// Load verified SMS attestation if present
		verifiedSMS := GetAttestation(req, t.UserID, "web3_sms")
		if len(verifiedSMS) > 0 {
			t.Attestations["sms"] = verifiedSMS
		}

		return t, nil
	}

	// Fall-through: No valid scopes matched against the provided web3 token
	return nil, fmt.Errorf("no valid web3 session token present")
}

func ParseWeb3Token(required_scope string, token string) (*Web3UserSession, error) {

	// Validate we have the 3 subsections of the token we expect (JWT standard = 3)
	targv := strings.Split(token, ".")
	if len(targv) != 3 {
		return nil, fmt.Errorf("[-] ERROR: unexpected number of token arguments - token validation failed")
	}

	// Extract the 3 distinct JWT sections
	encoded_header := targv[0]
	encoded_payload := targv[1]
	encoded_signature := targv[2]

	// Base64() URL decode the token header section
	headerBytes, err := base64URLDecode(encoded_header)
	if err != nil {
		return nil, err
	}

	// JSON Decode the Web3 Token Header section (Token Type & Algo Selection)
	var header Web3TokenHeader
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return nil, err
	}

	// Validate this is an ES256 JWT token or bail out now
	if header.Type != "JWT" || header.Algorithm != "ES256" {
		return nil, fmt.Errorf("[-] ERROR: Unsupported auth token type")
	}

	// Base64() URL decode the token payload section
	payloadBytes, err := base64URLDecode(encoded_payload)
	if err != nil {
		return nil, err
	}

	// JSON Decode the Web3 Token Payload section (User, Scope, IssuedAt, ExpiresAt)
	var payload Web3TokenPayload
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return nil, err
	}

	// Base64() URL decode the token ECDSA signature bytes
	signatureBytes, err := base64URLDecode(encoded_signature)
	if err != nil {
		return nil, err
	}

	// Decode the users public key - X component (aka Web3 ID)
	publicKeyX, err := base64URLDecode(payload.UserX)
	if err != nil {
		return nil, err
	}

	// Decode the users public key - Y component
	publicKeyY, err := base64URLDecode(payload.UserY)
	if err != nil {
		return nil, err
	}

	// Set up the SECP256 Public Key for validation
	ecpubkey := &ecdsa.PublicKey{Curve: elliptic.P256()}
	ecpubkey.X = new(big.Int).SetBytes(publicKeyX)
	ecpubkey.Y = new(big.Int).SetBytes(publicKeyY)

	// Setup the R & S components of the ECDSA validation
	sig := &ECDSASignature{}
	sig.R = new(big.Int).SetBytes(signatureBytes[0:32])
	sig.S = new(big.Int).SetBytes(signatureBytes[32:64])

	// Build the token challenge digest string
	challenge_digest := fmt.Sprintf("%s.%s", encoded_header, encoded_payload)

	// Generate a SHA256() hash of the callenge_digest for use in signature validation below
	hash := sha256.Sum256([]byte(challenge_digest))

	// Do signature validation across the token challenge digest against callers public ECC key
	isValidSignature := ecdsa.Verify(ecpubkey, hash[:], sig.R, sig.S)

	// Did we get a valid ECDSA signature? If not bail out now
	if !isValidSignature {
		return nil, fmt.Errorf("[-] GOT INVALID TOKEN!!! - User: \"%s\"", payload.UserX)
	}

	// Extract scope, creation/expiration time
	scope := payload.Scope
	now := time.Now()

	// Calculate allowable expiration window - 5 seconds of time skew allowed on either end
	issuedAt := time.Unix(payload.IssuedAt, 0).Add(-5 * time.Second)
	expiresAt := time.Unix(payload.ExpiresAt, 0).Add(5 * time.Second)

	// Enforce the required scope check name now
	if scope != required_scope {
		return nil, fmt.Errorf("[-] GOT INVALID TOKEN!!! - User: \"%s\" had incorrect scope: \"%s\"", payload.UserX, payload.Scope)
	}

	// Check token expiration status
	if now.Before(issuedAt) || now.After(expiresAt) {
		return nil, fmt.Errorf("[-] GOT EXPIRED TOKEN!!! - User: \"%s\"", payload.UserX)
	}

	// All security checks passed - Return a parsed web3 user token to the caller that is safe to use
	t := &Web3UserSession{UserID: payload.UserX, Scope: scope, CreatedAt: issuedAt, ExpiresAt: expiresAt, IsValid: true, Attestations: make(map[string]string)}

	return t, nil
}
