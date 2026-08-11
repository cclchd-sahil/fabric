/*
Copyright the MST integration contributors.
SPDX-License-Identifier: Apache-2.0
*/

package mstanchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	gp "github.com/hyperledger/fabric-protos-go/gateway"
	mspproto "github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/bccsp/vault"
	"github.com/hyperledger/fabric/protoutil"

	"github.com/hansrajrami/fabric/mst/relay/outbox"
	"github.com/hansrajrami/fabric/mst/relay/sender"
)

// statusConfirmed mirrors fabricwb.StatusConfirmed for the embedded path.
const statusConfirmed = "CONFIRMED"

// writeBackTimeout bounds one RecordAnchor round trip (endorse + order +
// commit). Failures re-park the entry at CONFIRMED; the sender retries and
// RecordAnchor is idempotent.
const writeBackTimeout = 2 * time.Minute

// GatewayInvoker is the in-process slice of the peer's gateway server the
// write-back needs for ordering + commit; *gateway.Server satisfies it.
// Calling the server's Go methods directly avoids a loopback network hop.
//
// Note the write-back does NOT use the gateway's Endorse: that path plans
// endorsement via discovery, which requires _lifecycle chaincode metadata.
// mstscc is a built-in system chaincode with no such metadata, so gateway
// Endorse fails ("No metadata was found for chaincode mstscc"). Endorsement
// is done directly against the local endorser (EndorserProcessor) instead;
// only ordering (Submit) and commit polling (CommitStatus) go through the
// gateway, both of which are stateless with respect to chaincode metadata.
type GatewayInvoker interface {
	Submit(ctx context.Context, request *gp.SubmitRequest) (*gp.SubmitResponse, error)
	CommitStatus(ctx context.Context, signedRequest *gp.SignedCommitStatusRequest) (*gp.CommitStatusResponse, error)
}

// EndorserProcessor is the in-process slice of the peer's local endorser the
// write-back uses to endorse the RecordAnchor proposal; *endorser.Endorser
// satisfies it. Endorsing here (rather than via the gateway) is what lets the
// write-back target the built-in mstscc, which has no discovery metadata.
type EndorserProcessor interface {
	ProcessProposal(ctx context.Context, signedProp *peer.SignedProposal) (*peer.ProposalResponse, error)
}

// LoopbackWriteBack records anchor status on Fabric by submitting
// RecordAnchor transactions through the peer's own embedded endorser and
// gateway, signed with the relayer's Fabric identity.
type LoopbackWriteBack struct {
	endorser  EndorserProcessor
	gateway   GatewayInvoker
	signer    *identitySigner
	chaincode string
}

var _ sender.WriteBack = (*LoopbackWriteBack)(nil)

// NewLoopbackWriteBack loads the relayer identity and wraps the local
// endorser (for endorsement) and gateway (for ordering + commit).
func NewLoopbackWriteBack(endorser EndorserProcessor, gateway GatewayInvoker, chaincode string, wb WriteBackConfig) (*LoopbackWriteBack, error) {
	signer, err := newIdentitySigner(wb)
	if err != nil {
		return nil, err
	}
	return &LoopbackWriteBack{endorser: endorser, gateway: gateway, signer: signer, chaincode: chaincode}, nil
}

// Record submits RecordAnchor(fabricTxID, evmTxHash, CONFIRMED) and waits
// for commit. Idempotent end to end: the chaincode is a quiet no-op for an
// already-recorded id.
func (w *LoopbackWriteBack) Record(ctx context.Context, e *outbox.Entry) error {
	ctx, cancel := context.WithTimeout(ctx, writeBackTimeout)
	defer cancel()

	fabricTxIDHex := hex.EncodeToString(e.FabricTxID[:])

	// Skip the write-back when the anchor is already recorded on the ledger — by
	// another anchoring peer, another relayer, or a prior attempt. This avoids
	// submitting a redundant RecordAnchor that would only no-op (or lose an MVCC
	// race in the same block), which keeps the extra ordering load and the
	// committer's MVCC_READ_CONFLICT warnings off the channel. A pre-check
	// failure is not fatal: fall through and let RecordAnchor's own idempotency
	// handle it. It cannot eliminate the tight same-block race (two peers both
	// see "not recorded" before either commits); that case still resolves via
	// RecordAnchor idempotency + the MVCC_READ_CONFLICT-as-success handling below.
	if recorded, err := w.alreadyRecorded(ctx, e.ChannelID, fabricTxIDHex); err == nil && recorded {
		return nil
	}

	args := [][]byte{
		[]byte("RecordAnchor"),
		[]byte(fabricTxIDHex),
		[]byte("0x" + hex.EncodeToString(e.EVMTxHash[:])),
		[]byte(statusConfirmed),
	}
	cis := &peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			Type:        peer.ChaincodeSpec_GOLANG,
			ChaincodeId: &peer.ChaincodeID{Name: w.chaincode},
			Input:       &peer.ChaincodeInput{Args: args},
		},
	}
	creator, err := w.signer.Serialize()
	if err != nil {
		return fmt.Errorf("mstanchor: serialize identity: %w", err)
	}
	proposal, txID, err := protoutil.CreateChaincodeProposal(
		common.HeaderType_ENDORSER_TRANSACTION, e.ChannelID, cis, creator,
	)
	if err != nil {
		return fmt.Errorf("mstanchor: build proposal: %w", err)
	}
	signedProposal, err := protoutil.GetSignedProposal(proposal, w.signer)
	if err != nil {
		return fmt.Errorf("mstanchor: sign proposal: %w", err)
	}

	// Endorse directly against the local endorser rather than the gateway:
	// mstscc is a built-in system chaincode with no discovery/_lifecycle
	// metadata, so the gateway's endorsement planning cannot find it. The
	// local endorser runs mstscc in-process and endorses unconditionally.
	response, err := w.endorser.ProcessProposal(ctx, signedProposal)
	if err != nil {
		return fmt.Errorf("mstanchor: endorse RecordAnchor: %w", err)
	}
	if s := response.GetResponse().GetStatus(); s < 200 || s >= 400 {
		return fmt.Errorf("mstanchor: RecordAnchor endorsement failed (%d): %s",
			s, response.GetResponse().GetMessage())
	}

	// Assemble and sign the transaction envelope from the endorsed response;
	// gateway.Submit only orders an already-signed envelope, so it does not
	// need the chaincode metadata the endorsement path lacks.
	envelope, err := protoutil.CreateSignedTx(proposal, w.signer, response)
	if err != nil {
		return fmt.Errorf("mstanchor: assemble transaction: %w", err)
	}

	if _, err := w.gateway.Submit(ctx, &gp.SubmitRequest{
		TransactionId:       txID,
		ChannelId:           e.ChannelID,
		PreparedTransaction: envelope,
	}); err != nil {
		return fmt.Errorf("mstanchor: submit RecordAnchor: %w", err)
	}

	statusRequest := &gp.CommitStatusRequest{
		ChannelId:     e.ChannelID,
		TransactionId: txID,
		Identity:      creator,
	}
	requestBytes, err := proto.Marshal(statusRequest)
	if err != nil {
		return fmt.Errorf("mstanchor: marshal status request: %w", err)
	}
	signature, err := w.signer.Sign(requestBytes)
	if err != nil {
		return fmt.Errorf("mstanchor: sign status request: %w", err)
	}
	statusResponse, err := w.gateway.CommitStatus(ctx, &gp.SignedCommitStatusRequest{
		Request:   requestBytes,
		Signature: signature,
	})
	if err != nil {
		return fmt.Errorf("mstanchor: commit status: %w", err)
	}
	switch statusResponse.GetResult() {
	case peer.TxValidationCode_VALID:
		// Recorded by this transaction.
	case peer.TxValidationCode_MVCC_READ_CONFLICT:
		// A concurrent RecordAnchor for the same fabricTxID committed first.
		// This tx's read set is only the deterministic anchor key (requirePeer
		// reads the MSP, not the ledger), so an MVCC conflict here can only mean
		// the anchor is already on the ledger — first-write-wins and idempotent.
		// Our goal is met, so treat it as success rather than re-parking the
		// entry. This is the expected outcome when a duplicate write-back races
		// (e.g. a relayer restart re-submits an already-ordered anchor).
	default:
		return fmt.Errorf("mstanchor: RecordAnchor invalidated: %s", statusResponse.GetResult())
	}
	return nil
}

// alreadyRecorded reports whether the anchor for fabricTxIDHex is already on the
// channel's ledger, via a read-only IsAnchored query against the local endorser
// (no ordering). IsAnchored is not identity-gated, so the relayer identity may
// call it. A query error is returned to the caller, which treats it as "not
// known to be recorded" and proceeds.
func (w *LoopbackWriteBack) alreadyRecorded(ctx context.Context, channelID, fabricTxIDHex string) (bool, error) {
	cis := &peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			Type:        peer.ChaincodeSpec_GOLANG,
			ChaincodeId: &peer.ChaincodeID{Name: w.chaincode},
			Input:       &peer.ChaincodeInput{Args: [][]byte{[]byte("IsAnchored"), []byte(fabricTxIDHex)}},
		},
	}
	creator, err := w.signer.Serialize()
	if err != nil {
		return false, err
	}
	proposal, _, err := protoutil.CreateChaincodeProposal(common.HeaderType_ENDORSER_TRANSACTION, channelID, cis, creator)
	if err != nil {
		return false, err
	}
	signedProposal, err := protoutil.GetSignedProposal(proposal, w.signer)
	if err != nil {
		return false, err
	}
	resp, err := w.endorser.ProcessProposal(ctx, signedProposal)
	if err != nil {
		return false, err
	}
	if s := resp.GetResponse().GetStatus(); s < 200 || s >= 400 {
		return false, fmt.Errorf("mstanchor: IsAnchored query failed (%d): %s", s, resp.GetResponse().GetMessage())
	}
	return string(resp.GetResponse().GetPayload()) == "true", nil
}

// identitySigner is a minimal Fabric signing identity: SHA-256 + low-S ECDSA
// (Fabric rejects high-S signatures), creator = the standard SerializedIdentity
// proto. The private key is either loaded from a PEM file (key) or held in the
// org's Vault Transit engine and signed remotely (csp+vaultKey). It implements
// protoutil.Signer.
type identitySigner struct {
	creator []byte

	// File-based key. Set when signing locally from a PEM key file.
	key *ecdsa.PrivateKey

	// Vault Transit-backed signing. Set when the write-back signs through the
	// org Transit engine; the private key never leaves Vault.
	csp      bccsp.BCCSP
	vaultKey bccsp.Key
}

var _ protoutil.Signer = (*identitySigner)(nil)

func newIdentitySigner(wb WriteBackConfig) (*identitySigner, error) {
	if wb.MSPID == "" || wb.CertPath == "" {
		return nil, fmt.Errorf("mstanchor: write-back requires mst.writeback mspID and certPath")
	}
	certPEM, err := os.ReadFile(wb.CertPath)
	if err != nil {
		return nil, fmt.Errorf("mstanchor: read write-back cert: %w", err)
	}
	creator, err := proto.Marshal(&mspproto.SerializedIdentity{Mspid: wb.MSPID, IdBytes: certPEM})
	if err != nil {
		return nil, fmt.Errorf("mstanchor: serialize identity: %w", err)
	}

	// Vault Transit signing: only when a username is given AND the peer's BCCSP
	// is Vault-backed. The private key stays in Vault, so no key file is needed;
	// the cert is still required to present the identity and pass mstscc's
	// peer-role gate.
	if wb.VaultUsername != "" {
		if wb.Vault == nil {
			return nil, fmt.Errorf("mstanchor: mst.writeback.vaultUsername is set but the peer BCCSP is not configured with VAULT")
		}
		csp, key, err := newVaultWriteBackKey(wb.Vault, wb.VaultUsername)
		if err != nil {
			return nil, err
		}
		// A Transit signature would be rejected by MSP validation if it did not
		// match the presented cert, so fail fast on a mismatch.
		if err := assertCertMatchesKey(certPEM, key, wb.VaultUsername); err != nil {
			return nil, err
		}
		return &identitySigner{creator: creator, csp: csp, vaultKey: key}, nil
	}

	if wb.KeyPath == "" {
		return nil, fmt.Errorf("mstanchor: write-back requires mst.writeback.keyPath (or set mst.writeback.vaultUsername with a Vault-backed BCCSP)")
	}
	keyPEM, err := os.ReadFile(wb.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("mstanchor: read write-back key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("mstanchor: write-back key is not PEM")
	}
	ecKey, err := parseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mstanchor: parse write-back key: %w", err)
	}
	return &identitySigner{creator: creator, key: ecKey}, nil
}

// newVaultWriteBackKey builds a Vault Transit-backed BCCSP for the write-back
// identity, keyed by username (the Transit key at <OrgName>_Transit/keys/<username>,
// the same layout as the Vault BCCSP plugin), and fetches its key handle.
func newVaultWriteBackKey(vc *VaultIdentityConfig, username string) (bccsp.BCCSP, bccsp.Key, error) {
	security := vc.Security
	if security == 0 {
		security = 256
	}
	hash := vc.Hash
	if hash == "" {
		hash = "SHA2"
	}
	csp, err := vault.New(vault.VaultOpts{
		Security:           security,
		Hash:               hash,
		Address:            vc.Address,
		Token:              vc.Token,
		OrgName:            vc.OrgName,
		KeyStore:           username,
		SoftwareVerify:     true,
		InsecureSkipVerify: vc.InsecureSkipVerify,
	}, sw.NewDummyKeyStore())
	if err != nil {
		return nil, nil, fmt.Errorf("mstanchor: init vault write-back signer: %w", err)
	}
	key, err := csp.GetKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("mstanchor: fetch vault write-back key %q: %w", username, err)
	}
	if key == nil || !key.Private() {
		return nil, nil, fmt.Errorf("mstanchor: vault write-back key %q is not a usable private key", username)
	}
	return csp, key, nil
}

// assertCertMatchesKey verifies the presented cert and the Vault Transit key are
// the same keypair; otherwise every write-back signature would be rejected by
// MSP validation.
func assertCertMatchesKey(certPEM []byte, key bccsp.Key, username string) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("mstanchor: write-back cert is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("mstanchor: parse write-back cert: %w", err)
	}
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("mstanchor: write-back cert public key must be ECDSA, got %T", cert.PublicKey)
	}
	certDER, err := x509.MarshalPKIXPublicKey(certPub)
	if err != nil {
		return fmt.Errorf("mstanchor: marshal write-back cert public key: %w", err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		return fmt.Errorf("mstanchor: vault write-back public key: %w", err)
	}
	keyDER, err := pub.Bytes()
	if err != nil {
		return fmt.Errorf("mstanchor: marshal vault write-back public key: %w", err)
	}
	if !bytes.Equal(certDER, keyDER) {
		return fmt.Errorf("mstanchor: write-back cert public key does not match Vault Transit key %q; they must be the same keypair", username)
	}
	return nil
}

// parseECPrivateKey parses an ECDSA private key from DER in either PKCS#8
// ("BEGIN PRIVATE KEY") or SEC1 ("BEGIN EC PRIVATE KEY") form. Fabric MSP
// keystores are PKCS#8, but cryptogen, some CAs, and openssl commonly emit
// SEC1, so accept both rather than forcing operators to convert the key.
func parseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("write-back key must be ECDSA, got %T", k)
		}
		return ec, nil
	}
	ec, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("write-back key is not a PKCS#8 or SEC1 ECDSA private key: %w", err)
	}
	return ec, nil
}

func (s *identitySigner) Serialize() ([]byte, error) { return s.creator, nil }

func (s *identitySigner) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	if s.csp != nil {
		// Vault Transit signs the prehashed digest and normalizes to low-S.
		return s.csp.Sign(s.vaultKey, digest[:], nil)
	}
	sig, err := s.key.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return nil, err
	}
	return utils.SignatureToLowS(&s.key.PublicKey, sig)
}
