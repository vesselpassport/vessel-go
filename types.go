package vessel

import (
	"math/big"
	"time"

	"github.com/golang-jwt/jwt"
)

type VesselClaims struct {
	AttestationType string `json:"ats_type"`
	AttestationData string `json:"ats_data"`
	jwt.StandardClaims
}

type Web3UserSession struct {
	UserID       string
	Scope        string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	IsValid      bool
	Attestations map[string]string
}

// Web3TokenHeader - Primary JWT header describing Algorithm choice and token type
type Web3TokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type Web3TokenPayload struct {
	UserX     string `json:"sub"`
	UserY     string `json:"ecy"`
	Scope     string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type ECDSASignature struct {
	R, S *big.Int
}
