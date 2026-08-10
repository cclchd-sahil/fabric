/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	vaultAPI "github.com/hashicorp/vault/api"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/pkg/errors"
)

// Provider is a BCCSP implementation that offloads ECDSA key generation,
// signing and verification to a HashiCorp Vault Transit secrets engine.
// All operations that are not backed by Vault (hashing, AES, key import, ...)
// are delegated to an embedded software-based BCCSP.
type Provider struct {
	bccsp.BCCSP
	conf       *config
	address    string
	token      string
	keystore   string
	softVerify bool
	client     *vaultAPI.Client
	orgName    string
}

// New returns a HashiCorp Vault-backed BCCSP.
func New(opts VaultOpts, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(opts.Security, opts.Hash)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration at [%v,%v]", opts.Security, opts.Hash)
	}

	swCSP, err := sw.NewWithParams(opts.Security, opts.Hash, keyStore)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing fallback SW BCCSP")
	}

	clientConfig := &vaultAPI.Config{
		Address: opts.Address,
		HttpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: opts.InsecureSkipVerify,
				},
			},
		},
	}

	client, err := vaultAPI.NewClient(clientConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing vault client")
	}

	client.SetToken(opts.Token)

	csp := &Provider{
		BCCSP:      swCSP,
		conf:       conf,
		address:    opts.Address,
		token:      opts.Token,
		client:     client,
		keystore:   opts.KeyStore,
		softVerify: opts.SoftwareVerify,
		orgName:    strings.ToLower(opts.OrgName),
	}

	return csp, nil
}

// KeyGen generates a key using opts.
func (csp *Provider) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil")
	}

	switch opts.(type) {
	case *bccsp.ECDSAKeyGenOpts:
		ski, pub, err := csp.generateECKey(csp.conf.ellipticCurve, opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating ECDSA key")
		}
		k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pub}}

	case *bccsp.ECDSAP256KeyGenOpts:
		ski, pub, err := csp.generateECKey(elliptic.P256(), opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating ECDSA P256 key")
		}
		k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pub}}

	case *bccsp.ECDSAP384KeyGenOpts:
		ski, pub, err := csp.generateECKey(elliptic.P384(), opts.Ephemeral())
		if err != nil {
			return nil, errors.Wrapf(err, "Failed generating ECDSA P384 key")
		}
		k = &ecdsaPrivateKey{ski, ecdsaPublicKey{ski, pub}}

	default:
		return csp.BCCSP.KeyGen(opts)
	}

	return k, nil
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *Provider) GetKey(ski []byte) (bccsp.Key, error) {
	// Fetch the key from HashiCorp Vault
	response, err := csp.fetchKey()
	if err != nil {
		// Fall back to the SW BCCSP's GetKey method if the key is not found in Vault
		return csp.BCCSP.GetKey(ski)
	}

	publicKeyPEM, err := getPublicKeyPem(response)
	if err != nil {
		return nil, err
	}

	publicKey, err := getECDSAPublicKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}

	generatedSki := getSKI(publicKey)

	return &ecdsaPrivateKey{generatedSki, ecdsaPublicKey{generatedSki, publicKey}}, nil
}

// Sign signs digest using key k.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *Provider) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty")
	}

	switch key := k.(type) {
	case *ecdsaPrivateKey:
		return csp.signECDSA(*key, digest)
	default:
		return csp.BCCSP.Sign(k, digest, opts)
	}
}

// Verify verifies signature against key k and digest.
func (csp *Provider) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty")
	}

	switch key := k.(type) {
	case *ecdsaPrivateKey:
		return csp.verifyECDSA(key.pub, signature, digest)
	case *ecdsaPublicKey:
		return csp.verifyECDSA(*key, signature, digest)
	default:
		return csp.BCCSP.Verify(k, signature, digest, opts)
	}
}

func (csp *Provider) signECDSA(k ecdsaPrivateKey, digest []byte) ([]byte, error) {
	data := map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(digest),
		"prehashed": true,
	}

	response, err := csp.client.Logical().Write(csp.transitPath("sign"), data)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Data == nil {
		return nil, errors.New("Vault: empty response on sign")
	}

	rawSignature, ok := response.Data["signature"].(string)
	if !ok {
		return nil, errors.New("Vault: missing 'signature' in response")
	}

	// Vault signatures are formatted as "vault:v<n>:<base64-signature>".
	signatureset := strings.Split(rawSignature, ":")
	if len(signatureset) != 3 {
		return nil, errors.New("Invalid signature. Check vault version")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureset[2])
	if err != nil {
		return nil, err
	}

	r, s, err := utils.UnmarshalECDSASignature(signatureBytes)
	if err != nil {
		return nil, err
	}

	s, err = utils.ToLowS(k.pub.pub, s)
	if err != nil {
		return nil, err
	}

	return utils.MarshalECDSASignature(r, s)
}

func (csp *Provider) verifyECDSA(k ecdsaPublicKey, signature, digest []byte) (bool, error) {
	r, s, err := utils.UnmarshalECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	lowS, err := utils.IsLowS(k.pub, s)
	if err != nil {
		return false, err
	}
	if !lowS {
		return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s]", s, utils.GetCurveHalfOrdersAt(k.pub.Curve))
	}

	if csp.softVerify {
		return ecdsa.Verify(k.pub, digest, r, s), nil
	}

	return csp.verifyVaultECDSA(signature, digest)
}

func (csp *Provider) generateECKey(curve elliptic.Curve, ephemeral bool) (ski []byte, pubKey *ecdsa.PublicKey, err error) {
	var curveName string
	switch curve.Params().Name {
	case "P-256":
		curveName = "ecdsa-p256"
	case "P-384":
		curveName = "ecdsa-p384"
	case "P-521":
		curveName = "ecdsa-p521"
	default:
		return nil, nil, fmt.Errorf("Vault: unsupported curve [%s]", curve.Params().Name)
	}

	data := map[string]interface{}{
		"type":       curveName,
		"exportable": true,
	}

	if _, err = csp.client.Logical().Write(csp.transitPath("keys"), data); err != nil {
		return nil, nil, fmt.Errorf("Vault: keypair generate failed [%s]", err)
	}

	response, err := csp.fetchKey()
	if err != nil {
		return nil, nil, fmt.Errorf("Vault: keypair fetch failed [%s]", err)
	}

	publicKeyPEM, err := getPublicKeyPem(response)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := getECDSAPublicKey(publicKeyPEM)
	if err != nil {
		return nil, nil, err
	}

	ski = getSKI(publicKey)

	return ski, publicKey, nil
}

// fetchKey reads the Transit key material from Vault.
func (csp *Provider) fetchKey() (map[string]interface{}, error) {
	response, err := csp.client.Logical().Read(csp.transitPath("keys"))
	if err != nil {
		return nil, fmt.Errorf("failed getting ECDSA key: [%s]", err)
	}

	if response == nil || response.Data == nil {
		return nil, fmt.Errorf("Key not found")
	}

	return response.Data, nil
}

func (csp *Provider) verifyVaultECDSA(signature []byte, msg []byte) (bool, error) {
	vaultSig := base64.StdEncoding.EncodeToString(signature)
	vaultSignature := fmt.Sprintf("vault:v1:%s", vaultSig)

	data := map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(msg),
		"signature": vaultSignature,
		"prehashed": true,
	}

	response, err := csp.client.Logical().Write(csp.transitPath("verify"), data)
	if err != nil {
		return false, err
	}
	if response == nil || response.Data == nil {
		return false, errors.New("Vault: empty response on verify")
	}

	isValid, ok := response.Data["valid"].(bool)
	if !ok {
		return false, errors.New("Vault: missing 'valid' in response")
	}
	return isValid, nil
}

// transitPath builds the Transit engine path for the given operation, e.g.
// "<org>_Transit/sign/<keystore>".
func (csp *Provider) transitPath(operation string) string {
	return csp.orgName + "_Transit/" + operation + "/" + csp.keystore
}
