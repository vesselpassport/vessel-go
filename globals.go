package vessel

import "crypto/ecdsa"

// Vessel primary attestation token public key parameters
var gVesselPublicKeyX = "2890e20192d5da85f3281df77a64b88d39c216b0964c7d6feb67cf76e99e6de1"
var gVesselPublicKeyY = "12b05260ed58b932938d9665ea58e0531b45318b987ab5d7dd3461adc3ca8d65"

// Loaded key instance
var gVesselPublicKey *ecdsa.PublicKey
var gVesselPublicKeyBytes []byte

// Permitted Authentication Scopes (server names)
var gPermittedScopes []string
