/*
Copyright the MST integration contributors.
SPDX-License-Identifier: Apache-2.0
*/

// Package mstanchor embeds the MST proof-anchoring pipeline into the peer
// binary, behind the core.yaml `mst.enabled` flag (default off). It reuses
// the exact same proto-free capture core, durable outbox, and sender that
// the standalone mst-relayd daemon uses; only the block source (the peer's
// own ledger instead of the Gateway event API) and the configuration
// surface (core.yaml instead of a JSON file) differ.
//
// The commit path remains untouched even in embedded mode: blocks are read
// through the ledger's blocks iterator strictly AFTER commit, and every
// MST-facing operation is asynchronous behind the crash-safe outbox.
package mstanchor

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"

	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/core/scc/mstscc"

	"github.com/hansrajrami/fabric/mst/relay/capture"
	"github.com/hansrajrami/fabric/mst/relay/evm"
	"github.com/hansrajrami/fabric/mst/relay/sender"
)

// EnvRelayerKey is the environment variable holding the relayer's EVM
// private key (hex). It is intentionally NOT a core.yaml value.
const EnvRelayerKey = "MST_RELAYER_KEY"

// Config is the embedded relayer configuration, read from the peer's
// core.yaml `mst:` section.
type Config struct {
	Enabled bool
	// OutboxPath is the root directory for the durable outboxes (one
	// subdirectory per channel).
	OutboxPath string
	// Channels restricts anchoring to these channels; empty means every
	// channel the peer has joined.
	Channels []string
	// DefaultStartBlock applies when a channel has no checkpoint yet.
	DefaultStartBlock uint64

	// NOTE: the anchoring POLICY fields — capture mode, include/exclude
	// chaincodes, batch strategy, confirmations, and chain id — are NOT read
	// here. They are channel-governed (channelconfig.MSTAnchorConfig) so peers
	// cannot diverge on what/how/where to anchor. core.yaml keeps only
	// peer-local operational knobs.

	EVM struct {
		RPCURL                string
		InsecureSkipTLSVerify bool
		GasLimit              uint64
		TipCapGwei            uint64
		// MinBalanceGwei: log loudly when the relayer's gas balance drops
		// below this (0 disables the watcher; the metrics gauge is always
		// exposed regardless).
		MinBalanceGwei uint64
	}

	Sender struct {
		Workers        int
		BackoffMin     time.Duration
		BackoffMax     time.Duration
		ConfirmTimeout time.Duration
	}

	// Outbox backend AUTO-FOLLOWS the peer's ledger.state.stateDatabase:
	// goleveldb -> embedded LevelDB under OutboxPath; CouchDB -> dedicated
	// per-channel databases on the peer's own CouchDB server (never the
	// peer's state databases themselves). Connection settings come from
	// ledger.state.couchDBConfig, overridable via mst.outbox.couchDB.*.
	Outbox struct {
		Backend string // "leveldb" | "couchdb"
		CouchDB struct {
			Address  string
			Username string
			Password string
		}
	}

	// WriteBack is the relayer's Fabric identity used to submit RecordAnchor
	// through the peer's embedded gateway. The mst system chaincode requires a
	// PEER-role identity (NodeOUs), so this must be the peer's own node
	// signing identity, not a client cert.
	WriteBack WriteBackConfig

	// MetricsAddr serves /metrics and /healthz for the embedded relayer;
	// empty disables it (the peer's operations endpoint is separate).
	MetricsAddr string
}

// WriteBackConfig is the relayer's Fabric signing identity for RecordAnchor.
// The cert (with MSPID) presents the identity; the private key is taken either
// from KeyPath or, when VaultUsername is set and the peer BCCSP is Vault-backed,
// from the org Transit engine (Vault) — in which case KeyPath is not required.
type WriteBackConfig struct {
	MSPID    string
	CertPath string
	KeyPath  string
	// VaultUsername selects the Transit key (<OrgName>_Transit/keys/<username>)
	// that signs this identity. Only honored when Vault is set (peer BCCSP=VAULT).
	VaultUsername string
	// Vault carries the peer's Vault BCCSP connection, populated only when
	// peer.BCCSP.Default is VAULT.
	Vault *VaultIdentityConfig
}

// VaultIdentityConfig is the subset of the peer's Vault BCCSP configuration the
// write-back needs to sign its identity from the org Transit engine.
type VaultIdentityConfig struct {
	Address            string
	Token              string
	OrgName            string
	InsecureSkipVerify bool
	Security           int
	Hash               string
}

// FromViper reads the mst.* section from the peer's configuration. With
// mst.enabled absent or false, an all-zero disabled config is returned and
// the peer behaves exactly like vanilla Fabric.
func FromViper(v *viper.Viper) (*Config, error) {
	c := &Config{}
	c.Enabled = v.GetBool("mst.enabled")
	if !c.Enabled {
		return c, nil
	}

	c.OutboxPath = v.GetString("mst.outboxPath")
	c.Channels = v.GetStringSlice("mst.channels")
	c.DefaultStartBlock = uint64(v.GetInt64("mst.defaultStartBlock"))

	c.EVM.RPCURL = v.GetString("mst.evm.rpcURL")
	c.EVM.InsecureSkipTLSVerify = v.GetBool("mst.evm.insecureSkipTLSVerify")
	c.EVM.GasLimit = uint64(v.GetInt64("mst.evm.gasLimit"))
	c.EVM.TipCapGwei = uint64(v.GetInt64("mst.evm.tipCapGwei"))
	c.EVM.MinBalanceGwei = uint64(v.GetInt64("mst.evm.minBalanceGwei"))

	c.Sender.Workers = v.GetInt("mst.sender.workers")
	c.Sender.BackoffMin = v.GetDuration("mst.sender.backoffMin")
	c.Sender.BackoffMax = v.GetDuration("mst.sender.backoffMax")
	c.Sender.ConfirmTimeout = v.GetDuration("mst.sender.confirmTimeout")

	// Auto-follow the peer's state database choice.
	c.Outbox.Backend = "leveldb"
	if strings.EqualFold(v.GetString("ledger.state.stateDatabase"), "CouchDB") {
		c.Outbox.Backend = "couchdb"
		c.Outbox.CouchDB.Address = firstNonEmpty(
			v.GetString("mst.outbox.couchDB.address"),
			v.GetString("ledger.state.couchDBConfig.couchDBAddress"),
		)
		c.Outbox.CouchDB.Username = firstNonEmpty(
			v.GetString("mst.outbox.couchDB.username"),
			v.GetString("ledger.state.couchDBConfig.username"),
		)
		c.Outbox.CouchDB.Password = firstNonEmpty(
			v.GetString("mst.outbox.couchDB.password"),
			v.GetString("ledger.state.couchDBConfig.password"),
		)
		if c.Outbox.CouchDB.Address == "" {
			return nil, fmt.Errorf("mstanchor: state database is CouchDB but no couchDB address is configured")
		}
	}

	c.WriteBack.MSPID = v.GetString("mst.writeback.mspID")
	c.WriteBack.CertPath = v.GetString("mst.writeback.certPath")
	c.WriteBack.KeyPath = v.GetString("mst.writeback.keyPath")
	c.WriteBack.VaultUsername = v.GetString("mst.writeback.vaultUsername")
	// When the peer's BCCSP is Vault-backed, capture the connection so the
	// write-back can sign its identity from the org Transit engine (keyed by
	// vaultUsername) instead of a key file.
	if strings.EqualFold(v.GetString("peer.BCCSP.Default"), "VAULT") {
		c.WriteBack.Vault = &VaultIdentityConfig{
			Address:            v.GetString("peer.BCCSP.VAULT.Address"),
			Token:              v.GetString("peer.BCCSP.VAULT.Token"),
			OrgName:            v.GetString("peer.BCCSP.VAULT.OrgName"),
			InsecureSkipVerify: v.GetBool("peer.BCCSP.VAULT.InsecureSkipVerify"),
			Security:           v.GetInt("peer.BCCSP.VAULT.Security"),
			Hash:               v.GetString("peer.BCCSP.VAULT.Hash"),
		}
	}

	c.MetricsAddr = v.GetString("mst.metricsAddr")

	if c.OutboxPath == "" {
		return nil, fmt.Errorf("mstanchor: mst.outboxPath is required when mst.enabled is true")
	}
	// Only the RPC endpoint (a peer-local operational setting) is required
	// here. The contract address, chain id, capture scope, batch strategy, and
	// confirmations are all per-channel values carried in the channel
	// configuration. The EVM client learns its chain id from the node at dial
	// time; each channel's declared chainID is validated against it.
	if c.EVM.RPCURL == "" {
		return nil, fmt.Errorf("mstanchor: mst.evm.rpcURL is required when mst.enabled is true")
	}
	return c, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// couchDatabaseName derives the per-channel outbox database name. Channel
// ids match [a-z][a-z0-9.-]* and CouchDB forbids '.', so dots map to '_'
// (which cannot occur in channel ids — no collisions).
func couchDatabaseName(channelID string) string {
	return "mst_outbox_" + strings.ReplaceAll(channelID, ".", "_")
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// EVMConfig maps to the shared EVM client config; the key comes strictly
// from the environment. ChainID is left 0 so the client learns the real chain
// id from the node at dial time — each channel's declared chainID is then
// validated against it (see service.startNewPipelines).
func (c *Config) EVMConfig() (evm.Config, error) {
	key := os.Getenv(EnvRelayerKey)
	if key == "" {
		return evm.Config{}, fmt.Errorf("mstanchor: %s environment variable is required when mst.enabled is true", EnvRelayerKey)
	}
	return evm.Config{
		RPCURL:                c.EVM.RPCURL,
		InsecureSkipTLSVerify: c.EVM.InsecureSkipTLSVerify,
		PrivateKeyHex:         key,
		GasLimit:              c.EVM.GasLimit,
		TipCapGwei:            c.EVM.TipCapGwei,
	}, nil
}

// CaptureConfigFor builds the capture config for one channel: the capture
// scope (mode + include/exclude chaincodes) comes from the channel's own
// configuration, the start block is peer-local. The mst system chaincode is
// always excluded (echo-loop guard) regardless of the channel's exclude list.
func (c *Config) CaptureConfigFor(mst *channelconfig.MSTAnchorConfig) capture.Config {
	return capture.Config{
		Mode:              capture.Mode(mst.CaptureMode), // "" normalizes to opt-in
		DefaultStartBlock: c.DefaultStartBlock,
		ExcludeChaincodes: appendUnique(append([]string(nil), mst.ExcludeChaincodes...), mstscc.Name),
		IncludeChaincodes: mst.IncludeChaincodes,
	}
}

// SenderConfigFor builds the sender config for one channel: the batch strategy,
// confirmation threshold, and flush cadence come from the channel's
// configuration, while the peer-local knobs (workers, backoff, timeouts) come
// from core.yaml. The cadence durations are already validated by channelconfig,
// so any parse error here is treated as an unset (zero) value.
func (c *Config) SenderConfigFor(mst *channelconfig.MSTAnchorConfig) sender.Config {
	interval, _ := time.ParseDuration(mst.CadenceInterval)
	maxWait, _ := time.ParseDuration(mst.CadenceMaxWait)
	return sender.Config{
		Confirmations: mst.Confirmations,                       // 0 → the sender's built-in default
		Workers:       c.Sender.Workers,                        // peer-local
		Strategy:      sender.BatchStrategy(mst.BatchStrategy), // "" → individual
		Cadence: sender.Cadence{
			Mode:     sender.CadenceMode(mst.CadenceMode), // "" → per-tx
			N:        mst.CadenceN,
			Interval: interval,
			MaxWait:  maxWait,
			Cron:     mst.CadenceCron,
		},
		Backoff: sender.Backoff{
			Min: c.Sender.BackoffMin,
			Max: c.Sender.BackoffMax,
		},
		ConfirmTimeout: c.Sender.ConfirmTimeout,
	}
}

// channelAllowed reports whether the channel participates in anchoring.
func (c *Config) channelAllowed(channelID string) bool {
	if len(c.Channels) == 0 {
		return true
	}
	for _, ch := range c.Channels {
		if ch == channelID {
			return true
		}
	}
	return false
}
