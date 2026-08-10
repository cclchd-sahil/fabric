/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func pemToPublicKey(raw []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding. Block must be different from nil [% x]", raw)
	}

	return derToPublicKey(block.Bytes)
}

func derToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid DER. It must be different from nil")
	}

	return x509.ParsePKIXPublicKey(raw)
}

func getSKI(pubKey *ecdsa.PublicKey) []byte {
	raw := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// getPublicKeyPem extracts the latest version public key PEM returned by the
// Vault Transit engine when reading a key.
func getPublicKeyPem(data map[string]interface{}) (string, error) {
	keys, ok := data["keys"].(map[string]interface{})
	if !ok {
		return "", errors.New("Vault: unexpected response, missing 'keys' field")
	}

	// The Transit engine reports the current version under "latest_version".
	version := "1"
	if lv, ok := data["latest_version"]; ok {
		version = fmt.Sprintf("%v", lv)
	}

	entry, ok := keys[version].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("Vault: unexpected response, missing key version [%s]", version)
	}

	publicKey, ok := entry["public_key"].(string)
	if !ok {
		return "", errors.New("Vault: unexpected response, missing 'public_key' field")
	}

	return publicKey, nil
}

func getECDSAPublicKey(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	key, err := pemToPublicKey([]byte(publicKeyPEM))
	if err != nil {
		return nil, err
	}

	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Invalid ECDSA public key")
	}

	return publicKey, nil
}
