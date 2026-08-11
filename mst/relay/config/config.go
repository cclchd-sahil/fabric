// Package config loads the relayer daemon configuration. Everything about
// the MST chain and the Fabric peer is configuration; the relayer's EVM
// private key comes ONLY from the environment (MST_RELAYER_KEY), never from
// the config file, so files can be committed/distributed safely.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/hansrajrami/fabric/mst/relay/capture"
	"github.com/hansrajrami/fabric/mst/relay/evm"
	"github.com/hansrajrami/fabric/mst/relay/gwsource"
	"github.com/hansrajrami/fabric/mst/relay/outbox"
	"github.com/hansrajrami/fabric/mst/relay/sender"
)

// EnvRelayerKey is the environment variable holding the relayer's EVM
// private key (hex).
const EnvRelayerKey = "MST_RELAYER_KEY"

// File is the on-disk JSON shape.
type File struct {
	// OutboxPath is the LevelDB directory for the durable outbox (used when
	// outbox.type is empty or "leveldb").
	OutboxPath string `json:"outboxPath"`

	// Outbox optionally selects the backend. Default: embedded LevelDB at
	// OutboxPath. With type "couchdb" the outbox lives in a dedicated
	// database on a CouchDB server instead (typically the one the peer
	// already runs for its state database).
	Outbox struct {
		Type    string `json:"type"` // "" | "leveldb" | "couchdb"
		CouchDB struct {
			URL      string `json:"url"`
			Username string `json:"username"`
			Password string `json:"password"`
			Database string `json:"database"`
		} `json:"couchDB"`
	} `json:"outbox"`

	Fabric struct {
		Endpoint           string `json:"endpoint"`
		TLSCACertPath      string `json:"tlsCACertPath"`
		ServerNameOverride string `json:"serverNameOverride"`
		MSPID              string `json:"mspID"`
		CertPath           string `json:"certPath"`
		KeyPath            string `json:"keyPath"`
		Channel            string `json:"channel"`
		DefaultStartBlock  uint64 `json:"defaultStartBlock"`
		// CaptureMode: "opt-in" (default; only MSTProofRequest emitters) or
		// "all" (every valid transaction; non-opted txs get the empty
		// payload hash). Batch cadence is strongly advisable with "all".
		CaptureMode       string   `json:"captureMode"`
		ExcludeChaincodes []string `json:"excludeChaincodes"`
		// IncludeChaincodes restricts captureMode "all" to these chaincodes
		// (empty = every chaincode). Ignored in opt-in mode.
		IncludeChaincodes []string `json:"includeChaincodes"`
		// AnchorStatusChaincode is the write-back chaincode name. It is
		// force-added to ExcludeChaincodes (echo-loop guard) and used by the
		// write-back client.
		AnchorStatusChaincode string `json:"anchorStatusChaincode"`
	} `json:"fabric"`

	EVM struct {
		RPCURL                string `json:"rpcURL"`
		InsecureSkipTLSVerify bool   `json:"insecureSkipTLSVerify"`
		ContractAddress       string `json:"contractAddress"`
		ChainID               uint64 `json:"chainID"`
		GasLimit              uint64 `json:"gasLimit"`
		TipCapGwei            uint64 `json:"tipCapGwei"`
		Confirmations         uint64 `json:"confirmations"`
		// MinBalanceGwei: log loudly when the relayer's gas balance drops
		// below this (0 disables the watcher; the metrics gauge is always on).
		MinBalanceGwei uint64 `json:"minBalanceGwei"`
	} `json:"evm"`

	Sender struct {
		Workers int `json:"workers"`
		// BatchStrategy: "individual" (default; one on-chain record per tx,
		// multi-entry flushes share one EVM tx) or "merkle" (one root per
		// flush; verifiers need inclusion proofs from mst-proof).
		BatchStrategy      string `json:"batchStrategy"`
		CadenceMode        string `json:"cadenceMode"` // per-tx | batch | interval | cron
		CadenceN           int    `json:"cadenceN"`
		CadenceIntervalSec int    `json:"cadenceIntervalSeconds"`
		CadenceCron        string `json:"cadenceCron"` // 5-field cron for cadenceMode "cron"
		CadenceMaxWaitSec  int    `json:"cadenceMaxWaitSeconds"`
		BackoffMinSec      int    `json:"backoffMinSeconds"`
		BackoffMaxSec      int    `json:"backoffMaxSeconds"`
		ConfirmTimeoutSec  int    `json:"confirmTimeoutSeconds"`
	} `json:"sender"`

	// MetricsAddr serves /metrics (Prometheus text) and /healthz; empty
	// disables the endpoint.
	MetricsAddr string `json:"metricsAddr"`
}

// Load reads and validates the config file.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	switch f.Outbox.Type {
	case "", "leveldb":
		if f.OutboxPath == "" {
			return nil, fmt.Errorf("config: outboxPath is required")
		}
	case "couchdb":
		if f.Outbox.CouchDB.URL == "" || f.Outbox.CouchDB.Database == "" {
			return nil, fmt.Errorf("config: outbox.couchDB.url and outbox.couchDB.database are required for the couchdb outbox")
		}
	default:
		return nil, fmt.Errorf("config: unknown outbox.type %q", f.Outbox.Type)
	}
	if f.EVM.RPCURL == "" || f.EVM.ContractAddress == "" {
		return nil, fmt.Errorf("config: evm.rpcURL and evm.contractAddress are required")
	}
	if f.Fabric.Endpoint == "" || f.Fabric.Channel == "" {
		return nil, fmt.Errorf("config: fabric.endpoint and fabric.channel are required")
	}
	if f.Fabric.AnchorStatusChaincode != "" {
		f.Fabric.ExcludeChaincodes = appendUnique(f.Fabric.ExcludeChaincodes, f.Fabric.AnchorStatusChaincode)
	}
	mode := capture.Mode(f.Fabric.CaptureMode)
	if err := mode.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	f.Fabric.CaptureMode = string(mode)
	return &f, nil
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// OpenOutbox opens the configured outbox backend.
func (f *File) OpenOutbox() (outbox.Store, error) {
	if f.Outbox.Type == "couchdb" {
		return outbox.OpenCouchDB(outbox.CouchDBOptions{
			URL:      f.Outbox.CouchDB.URL,
			Username: f.Outbox.CouchDB.Username,
			Password: f.Outbox.CouchDB.Password,
			Database: f.Outbox.CouchDB.Database,
		})
	}
	return outbox.Open(f.OutboxPath, nil)
}

// GatewayConfig maps to the capture source configuration.
func (f *File) GatewayConfig() gwsource.Config {
	return gwsource.Config{
		Endpoint:           f.Fabric.Endpoint,
		TLSCACertPath:      f.Fabric.TLSCACertPath,
		ServerNameOverride: f.Fabric.ServerNameOverride,
		MSPID:              f.Fabric.MSPID,
		CertPath:           f.Fabric.CertPath,
		KeyPath:            f.Fabric.KeyPath,
		Channel:            f.Fabric.Channel,
	}
}

// CaptureConfig maps to the capture service configuration.
func (f *File) CaptureConfig() capture.Config {
	return capture.Config{
		Mode:              capture.Mode(f.Fabric.CaptureMode),
		DefaultStartBlock: f.Fabric.DefaultStartBlock,
		ExcludeChaincodes: f.Fabric.ExcludeChaincodes,
		IncludeChaincodes: f.Fabric.IncludeChaincodes,
	}
}

// EVMConfig maps to the EVM client configuration; the key is read from the
// environment.
func (f *File) EVMConfig() (evm.Config, error) {
	key := os.Getenv(EnvRelayerKey)
	if key == "" {
		return evm.Config{}, fmt.Errorf("config: %s environment variable is required", EnvRelayerKey)
	}
	return evm.Config{
		RPCURL:                f.EVM.RPCURL,
		InsecureSkipTLSVerify: f.EVM.InsecureSkipTLSVerify,
		ContractAddress:       f.EVM.ContractAddress,
		PrivateKeyHex:         key,
		ChainID:               f.EVM.ChainID,
		GasLimit:              f.EVM.GasLimit,
		TipCapGwei:            f.EVM.TipCapGwei,
	}, nil
}

// SenderConfig maps to the sender configuration.
func (f *File) SenderConfig() sender.Config {
	return sender.Config{
		Confirmations: f.EVM.Confirmations,
		Workers:       f.Sender.Workers,
		Strategy:      sender.BatchStrategy(f.Sender.BatchStrategy),
		Cadence: sender.Cadence{
			Mode:     sender.CadenceMode(f.Sender.CadenceMode),
			N:        f.Sender.CadenceN,
			Interval: time.Duration(f.Sender.CadenceIntervalSec) * time.Second,
			MaxWait:  time.Duration(f.Sender.CadenceMaxWaitSec) * time.Second,
			Cron:     f.Sender.CadenceCron,
		},
		Backoff: sender.Backoff{
			Min: time.Duration(f.Sender.BackoffMinSec) * time.Second,
			Max: time.Duration(f.Sender.BackoffMaxSec) * time.Second,
		},
		ConfirmTimeout: time.Duration(f.Sender.ConfirmTimeoutSec) * time.Second,
	}
}
