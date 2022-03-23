package vessel

import (
	"net/http"

	"github.com/golang-jwt/jwt"
)

// This function verifies the validity of a given vessel attestation token and if valid returns the embedded
// attestation data field back to the caller
func GetAttestation(req *http.Request, owner string, tokenName string) string {

	// Extract the web3 auth token from the web3auth cookie value if present
	cookie, err := req.Cookie(tokenName)
	if err != nil || cookie == nil {
		return ""
	}

	web3Token := cookie.Value

	// Initialize a new instance of `Claims`
	parseclaims := &VesselClaims{}

	// Lets do a test parse against the public key to make sure we've issued a valid attestation token
	tkn, err := jwt.ParseWithClaims(web3Token, parseclaims, func(token *jwt.Token) (interface{}, error) {
		return gVesselPublicKey, nil
	})

	// Sanity check for errors
	if err != nil {
		return ""
	}

	// Sanity check the token is actually valid
	if !tkn.Valid {
		return ""
	}

	// Finally verify the attestation token is issued to the correct owner
	if parseclaims.StandardClaims.Subject != owner {
		return ""
	}

	return parseclaims.AttestationData
}
