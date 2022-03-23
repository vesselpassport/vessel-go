package vessel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"log"
	"math/big"
)

func init() {
	publicKey, err := loadECDSA()
	if err != nil {
		log.Fatal(err.Error())
	}

	publicKeyBytes := elliptic.Marshal(elliptic.P256(), publicKey.X, publicKey.Y)

	// Set the active attestation validation key
	gVesselPublicKey = publicKey
	gVesselPublicKeyBytes = publicKeyBytes

	// Allocate permitted scopes list - no scopes permitted by default
	gPermittedScopes = make([]string, 0)
}

func loadECDSA() (*ecdsa.PublicKey, error) {
	publicKey := new(ecdsa.PublicKey)
	publicKey.Curve = elliptic.P256()
	publicKey.X, _ = new(big.Int).SetString(gVesselPublicKeyX, 16)
	publicKey.Y, _ = new(big.Int).SetString(gVesselPublicKeyY, 16)
	return publicKey, nil
}
