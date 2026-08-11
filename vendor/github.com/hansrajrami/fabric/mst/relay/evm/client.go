package evm

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gorilla/websocket"
)

// Config locates the MST chain and the relayer's key. Everything is plain
// configuration so pointing at the real MST network is a config-only change.
type Config struct {
	// RPCURL is the JSON-RPC endpoint (http(s) or ws(s)).
	RPCURL string
	// ContractAddress is the deployed MSTAnchor address (0x hex).
	ContractAddress string
	// PrivateKeyHex is the relayer's secp256k1 key (hex, no 0x needed).
	// Load it from an env var or secret store — never from a committed file.
	PrivateKeyHex string
	// ChainID; if zero it is fetched from the node at startup.
	ChainID uint64
	// GasLimit for anchor transactions (default 200000, plus 60000 per extra
	// batch element).
	GasLimit uint64
	// TipCapGwei is the priority fee; 0 lets the node suggest.
	TipCapGwei uint64
	// InsecureSkipTLSVerify disables TLS certificate verification for HTTPS/WSS
	// RPC endpoints. Use only in development/test environments.
	InsecureSkipTLSVerify bool
	// ReceiptPollInterval controls confirmation polling (default 500ms).
	ReceiptPollInterval time.Duration
}

const (
	defaultGasLimit     = 200_000
	perBatchItemGas     = 60_000
	defaultReceiptPoll  = 500 * time.Millisecond
	basefeeHeadroomMult = 2 // maxFee = 2*baseFee + tip: survives fee spikes
)

// Client talks to the MSTAnchor contract through go-ethereum's ethclient
// with EIP-1559 transactions signed by a local key.
type Client struct {
	eth      *ethclient.Client
	key      *ecdsa.PrivateKey
	sender   common.Address
	contract common.Address
	chainID  *big.Int
	signer   types.Signer
	cfg      Config

	// nonce management: initialized from PendingNonceAt, advanced locally,
	// resynced on nonce errors. The mutex serializes submissions; parallel
	// sender workers still overlap on confirmation waits, which is where the
	// latency actually is.
	nonceMu     sync.Mutex
	nonce       uint64
	nonceInited bool
}

// Dial connects, derives the sender address, and pins the chain id.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.ReceiptPollInterval <= 0 {
		cfg.ReceiptPollInterval = defaultReceiptPoll
	}
	if cfg.GasLimit == 0 {
		cfg.GasLimit = defaultGasLimit
	}
	eth, err := dialETHClient(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("evm: dial %s: %w", cfg.RPCURL, err)
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.PrivateKeyHex, "0x"))
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("evm: parse relayer key: %w", err)
	}
	// ContractAddress is optional: the embedded per-channel path binds a
	// contract per channel via Bind() and leaves this empty. When set (sidecar
	// / Phase 1 single-contract path), it is the default contract for the
	// Client's own Submit/Get methods.
	var defaultContract common.Address
	if cfg.ContractAddress != "" {
		if !common.IsHexAddress(cfg.ContractAddress) {
			eth.Close()
			return nil, fmt.Errorf("evm: bad contract address %q", cfg.ContractAddress)
		}
		defaultContract = common.HexToAddress(cfg.ContractAddress)
	}

	chainID := new(big.Int).SetUint64(cfg.ChainID)
	if cfg.ChainID == 0 {
		chainID, err = eth.ChainID(ctx)
		if err != nil {
			eth.Close()
			return nil, fmt.Errorf("evm: fetch chain id: %w", err)
		}
	}

	return &Client{
		eth:      eth,
		key:      key,
		sender:   crypto.PubkeyToAddress(key.PublicKey),
		contract: defaultContract,
		chainID:  chainID,
		signer:   types.LatestSignerForChainID(chainID),
		cfg:      cfg,
	}, nil
}

func dialETHClient(ctx context.Context, cfg Config) (*ethclient.Client, error) {
	if !cfg.InsecureSkipTLSVerify {
		return ethclient.DialContext(ctx, cfg.RPCURL)
	}

	u, err := url.Parse(cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("evm: parse RPC URL: %w", err)
	}

	var opts []rpc.ClientOption
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		opts = append(opts, rpc.WithHTTPClient(&http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}))
	case "ws", "wss":
		opts = append(opts, rpc.WithWebsocketDialer(websocket.Dialer{TLSClientConfig: tlsCfg}))
	default:
		return nil, fmt.Errorf("evm: unsupported RPC URL scheme %q for insecure TLS override", u.Scheme)
	}

	rpcClient, err := rpc.DialOptions(ctx, cfg.RPCURL, opts...)
	if err != nil {
		return nil, err
	}
	return ethclient.NewClient(rpcClient), nil
}

// Binding pairs the shared Client (one relayer account, one serialized nonce
// sequence) with a specific per-channel contract address. It satisfies the
// sender's AnchorClient interface, so each channel's pipeline submits to its
// own MSTAnchor contract while every submission still flows through the single
// Client's nonce lock — avoiding the head-of-line nonce collisions that
// independent clients on one account would cause.
type Binding struct {
	client   *Client
	contract common.Address
}

// Bind returns a Binding to the given per-channel contract address. The
// address must be a 0x-prefixed 20-byte hex string.
func (c *Client) Bind(address string) (*Binding, error) {
	if !common.IsHexAddress(address) {
		return nil, fmt.Errorf("evm: bad contract address %q", address)
	}
	return &Binding{client: c, contract: common.HexToAddress(address)}, nil
}

// Contract returns the bound contract address (0x hex).
func (b *Binding) Contract() string { return b.contract.Hex() }

// SetRelayer calls setRelayer(relayer, allowed) on the bound contract to add or
// remove a wallet from the contract's relayer allowlist. It must be sent from
// the contract owner's account, so the Client must have been dialed with the
// owner's key. Returns the EVM transaction hash.
func (b *Binding) SetRelayer(ctx context.Context, relayer string, allowed bool) ([32]byte, error) {
	if !common.IsHexAddress(relayer) {
		return [32]byte{}, fmt.Errorf("evm: bad relayer address %q", relayer)
	}
	return b.client.submit(ctx, b.contract, packSetRelayer(common.HexToAddress(relayer), allowed), b.client.cfg.GasLimit)
}

// SetRelayer calls setRelayer on the Client's default contract (owner-only).
func (c *Client) SetRelayer(ctx context.Context, relayer string, allowed bool) ([32]byte, error) {
	if !common.IsHexAddress(relayer) {
		return [32]byte{}, fmt.Errorf("evm: bad relayer address %q", relayer)
	}
	return c.submit(ctx, c.contract, packSetRelayer(common.HexToAddress(relayer), allowed), c.cfg.GasLimit)
}

func (b *Binding) GetAnchor(ctx context.Context, fabricTxID [32]byte) (*AnchorRecord, error) {
	return b.client.getAnchorAt(ctx, b.contract, fabricTxID)
}

// AnchorTxHash recovers the anchoring transaction hash from the bound contract's
// Anchored event; see (*Client).AnchorTxHash.
func (b *Binding) AnchorTxHash(ctx context.Context, fabricTxID [32]byte) ([32]byte, error) {
	return b.client.anchorTxHashAt(ctx, b.contract, fabricTxID)
}

func (b *Binding) GetRoot(ctx context.Context, root [32]byte) (*RootRecord, error) {
	return b.client.getRootAt(ctx, b.contract, root)
}

func (b *Binding) SubmitAnchor(ctx context.Context, fabricTxID, commitment [32]byte, blockNumber uint64) ([32]byte, error) {
	return b.client.submit(ctx, b.contract, packAnchor(fabricTxID, commitment, blockNumber), b.client.cfg.GasLimit)
}

func (b *Binding) SubmitAnchorRoot(ctx context.Context, root [32]byte, leafCount uint64) ([32]byte, error) {
	return b.client.submit(ctx, b.contract, packAnchorRoot(root, leafCount), b.client.cfg.GasLimit)
}

func (b *Binding) SubmitAnchorBatch(ctx context.Context, ids, commitments [][32]byte, blockNumbers []uint64) ([32]byte, error) {
	data, err := packAnchorBatch(ids, commitments, blockNumbers)
	if err != nil {
		return [32]byte{}, err
	}
	gas := b.client.cfg.GasLimit + perBatchItemGas*uint64(len(ids))
	return b.client.submit(ctx, b.contract, data, gas)
}

// TxIncluded and WaitConfirmed operate on transaction hashes, not the
// contract, so they delegate straight to the shared client.
func (b *Binding) TxIncluded(ctx context.Context, txHash [32]byte) (bool, error) {
	return b.client.TxIncluded(ctx, txHash)
}

func (b *Binding) WaitConfirmed(ctx context.Context, txHash [32]byte, confirmations uint64) error {
	return b.client.WaitConfirmed(ctx, txHash, confirmations)
}

// Sender returns the relayer's EVM address.
func (c *Client) Sender() string { return c.sender.Hex() }

// ChainID returns the id of the chain the client is connected to (learned from
// the node at dial time unless pinned in config).
func (c *Client) ChainID() uint64 { return c.chainID.Uint64() }

// Balance returns the relayer account's current balance in wei. The account
// pays gas for every anchor; when it runs dry, anchoring stalls safely into
// the outbox but silently — the sender's balance watcher and metrics gauge
// exist to make that visible before it happens.
func (c *Client) Balance(ctx context.Context) (*big.Int, error) {
	balance, err := c.eth.BalanceAt(ctx, c.sender, nil)
	if err != nil {
		return nil, fmt.Errorf("evm: balance of %s: %w", c.sender.Hex(), err)
	}
	return balance, nil
}

// Close releases the RPC connection.
func (c *Client) Close() { c.eth.Close() }

// GetAnchor reads the anchor record for fabricTxID from the Client's default
// contract; nil when not anchored.
func (c *Client) GetAnchor(ctx context.Context, fabricTxID [32]byte) (*AnchorRecord, error) {
	return c.getAnchorAt(ctx, c.contract, fabricTxID)
}

func (c *Client) getAnchorAt(ctx context.Context, contract common.Address, fabricTxID [32]byte) (*AnchorRecord, error) {
	data := packGetAnchor(fabricTxID)
	ret, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &contract, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("evm: getAnchor call: %w", err)
	}
	rec, err := unpackGetAnchor(ret)
	if err != nil {
		return nil, err
	}
	if !rec.Exists {
		return nil, nil
	}
	return rec, nil
}

// anchoredEventSig is topic[0] of the MSTAnchor Anchored event:
// keccak256("Anchored(bytes32,bytes32,uint64,uint64)"). fabricTxId is the sole
// indexed field, so it is topic[1].
var anchoredEventSig = crypto.Keccak256Hash([]byte("Anchored(bytes32,bytes32,uint64,uint64)"))

// AnchorTxHash recovers the EVM transaction hash that anchored fabricTxID from
// the Client's default contract by querying its Anchored event log (fabricTxId
// is indexed). It returns a zero hash and no error when no matching event is
// found (e.g. the node prunes logs, or the anchor predates the queried range).
// This backfills the write-back reference when the sender short-circuits an
// already-anchored entry and therefore never observed the original submission.
func (c *Client) AnchorTxHash(ctx context.Context, fabricTxID [32]byte) ([32]byte, error) {
	return c.anchorTxHashAt(ctx, c.contract, fabricTxID)
}

func (c *Client) anchorTxHashAt(ctx context.Context, contract common.Address, fabricTxID [32]byte) ([32]byte, error) {
	query := ethereum.FilterQuery{
		Addresses: []common.Address{contract},
		Topics: [][]common.Hash{
			{anchoredEventSig},
			{common.BytesToHash(fabricTxID[:])},
		},
	}
	logs, err := c.eth.FilterLogs(ctx, query)
	if err != nil {
		return [32]byte{}, fmt.Errorf("evm: filter Anchored logs: %w", err)
	}
	if len(logs) == 0 {
		return [32]byte{}, nil
	}
	// anchor is idempotent (a re-anchor is a no-op that emits no event), so at
	// most one Anchored event exists per fabricTxID; take the last defensively.
	return [32]byte(logs[len(logs)-1].TxHash), nil
}

// SubmitAnchor sends anchor(fabricTxID, commitment, blockNumber) to the
// Client's default contract and returns the EVM transaction hash without
// waiting for inclusion.
func (c *Client) SubmitAnchor(ctx context.Context, fabricTxID, commitment [32]byte, blockNumber uint64) ([32]byte, error) {
	return c.submit(ctx, c.contract, packAnchor(fabricTxID, commitment, blockNumber), c.cfg.GasLimit)
}

// SubmitAnchorRoot sends anchorRoot(root, leafCount) — one transaction
// anchoring a whole Merkle batch.
func (c *Client) SubmitAnchorRoot(ctx context.Context, root [32]byte, leafCount uint64) ([32]byte, error) {
	return c.submit(ctx, c.contract, packAnchorRoot(root, leafCount), c.cfg.GasLimit)
}

// GetRoot reads the batch-root record from the Client's default contract; nil
// when the root is not anchored.
func (c *Client) GetRoot(ctx context.Context, root [32]byte) (*RootRecord, error) {
	return c.getRootAt(ctx, c.contract, root)
}

func (c *Client) getRootAt(ctx context.Context, contract common.Address, root [32]byte) (*RootRecord, error) {
	data := packGetRoot(root)
	ret, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &contract, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("evm: getRoot call: %w", err)
	}
	rec, err := unpackGetRoot(ret)
	if err != nil {
		return nil, err
	}
	if !rec.Exists {
		return nil, nil
	}
	return rec, nil
}

// SubmitAnchorBatch sends anchorBatch for several entries in one transaction
// to the Client's default contract.
func (c *Client) SubmitAnchorBatch(ctx context.Context, ids, commitments [][32]byte, blockNumbers []uint64) ([32]byte, error) {
	data, err := packAnchorBatch(ids, commitments, blockNumbers)
	if err != nil {
		return [32]byte{}, err
	}
	gas := c.cfg.GasLimit + perBatchItemGas*uint64(len(ids))
	return c.submit(ctx, c.contract, data, gas)
}

func (c *Client) submit(ctx context.Context, contract common.Address, calldata []byte, gasLimit uint64) ([32]byte, error) {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()

	tip := new(big.Int)
	if c.cfg.TipCapGwei > 0 {
		tip.SetUint64(c.cfg.TipCapGwei * 1e9)
	} else {
		suggested, err := c.eth.SuggestGasTipCap(ctx)
		if err != nil {
			return [32]byte{}, fmt.Errorf("evm: suggest tip: %w", err)
		}
		tip = suggested
	}
	head, err := c.eth.HeaderByNumber(ctx, nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("evm: head: %w", err)
	}
	feeCap := new(big.Int).Add(tip, new(big.Int).Mul(head.BaseFee, big.NewInt(basefeeHeadroomMult)))

	send := func(nonce uint64) (common.Hash, error) {
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   c.chainID,
			Nonce:     nonce,
			GasTipCap: tip,
			GasFeeCap: feeCap,
			Gas:       gasLimit,
			To:        &contract,
			Data:      calldata,
		})
		signed, err := types.SignTx(tx, c.signer, c.key)
		if err != nil {
			return common.Hash{}, fmt.Errorf("evm: sign: %w", err)
		}
		if err := c.eth.SendTransaction(ctx, signed); err != nil {
			return common.Hash{}, err
		}
		return signed.Hash(), nil
	}

	nonce, err := c.currentNonceLocked(ctx)
	if err != nil {
		return [32]byte{}, err
	}
	hash, err := send(nonce)
	if err != nil && isNonceError(err) {
		// Some other process used our nonce (or a restart raced a pending
		// tx): resync once and retry.
		if err2 := c.resyncNonceLocked(ctx); err2 != nil {
			return [32]byte{}, err2
		}
		hash, err = send(c.nonce)
		nonce = c.nonce
	}
	if err != nil {
		return [32]byte{}, fmt.Errorf("evm: send: %w", err)
	}
	c.nonce = nonce + 1
	return hash, nil
}

func (c *Client) currentNonceLocked(ctx context.Context) (uint64, error) {
	if !c.nonceInited {
		if err := c.resyncNonceLocked(ctx); err != nil {
			return 0, err
		}
	}
	return c.nonce, nil
}

func (c *Client) resyncNonceLocked(ctx context.Context) error {
	n, err := c.eth.PendingNonceAt(ctx, c.sender)
	if err != nil {
		return fmt.Errorf("evm: pending nonce: %w", err)
	}
	c.nonce = n
	c.nonceInited = true
	return nil
}

func isNonceError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "nonce too low") ||
		strings.Contains(msg, "nonce too high") ||
		strings.Contains(msg, "replacement transaction underpriced") ||
		strings.Contains(msg, "already known")
}

// ErrReverted is returned when an anchor transaction was included but failed.
// The anchor contract's happy paths never revert (duplicates are no-ops), so
// a revert means misconfiguration (e.g. allowlist without this relayer).
var ErrReverted = errors.New("evm: transaction reverted")

// TxIncluded reports whether the transaction has a receipt yet.
func (c *Client) TxIncluded(ctx context.Context, txHash [32]byte) (bool, error) {
	_, err := c.eth.TransactionReceipt(ctx, common.Hash(txHash))
	if errors.Is(err, ethereum.NotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("evm: receipt: %w", err)
	}
	return true, nil
}

// WaitConfirmed blocks until txHash has the required number of confirmations
// (1 = included). It returns ErrReverted for an included-but-failed tx and
// ctx errors on timeout/cancel — the caller retries; idempotency makes that
// safe.
func (c *Client) WaitConfirmed(ctx context.Context, txHash [32]byte, confirmations uint64) error {
	if confirmations == 0 {
		confirmations = 1
	}
	ticker := time.NewTicker(c.cfg.ReceiptPollInterval)
	defer ticker.Stop()

	for {
		receipt, err := c.eth.TransactionReceipt(ctx, common.Hash(txHash))
		switch {
		case errors.Is(err, ethereum.NotFound):
			// Not yet included; keep polling.
		case err != nil:
			return fmt.Errorf("evm: receipt: %w", err)
		case receipt.Status != types.ReceiptStatusSuccessful:
			return fmt.Errorf("%w: %x", ErrReverted, txHash)
		default:
			head, err := c.eth.BlockNumber(ctx)
			if err != nil {
				return fmt.Errorf("evm: head number: %w", err)
			}
			// Reorg guard: the receipt block plus (confirmations-1)
			// descendants must exist.
			if head >= receipt.BlockNumber.Uint64()+confirmations-1 {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
