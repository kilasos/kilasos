package license

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/pem"
	"errors"
)

//go:embed public.pem
var publicKeyPEM []byte

func EmbeddedPublicKey() (ed25519.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("license: no PEM block found in public.pem")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, errors.New("license: unexpected PEM type: " + block.Type)
	}
	// PKCS#8 wrapping — last 32 bytes are the raw Ed25519 public key
	if len(block.Bytes) < 32 {
		return nil, errors.New("license: PEM key too short")
	}
	key := block.Bytes[len(block.Bytes)-32:]
	return ed25519.PublicKey(key), nil
}
