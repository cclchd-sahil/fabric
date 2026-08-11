/*
Copyright the MST integration contributors.
SPDX-License-Identifier: Apache-2.0
*/

package mstanchor

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/core/scc/mstscc"

	"github.com/hansrajrami/fabric/mst/relay/capture"
	"github.com/hansrajrami/fabric/mst/relay/sender"
)

func TestDisabledByDefault(t *testing.T) {
	v := viper.New()
	cfg, err := FromViper(v)
	require.NoError(t, err)
	require.False(t, cfg.Enabled, "mst must be off unless explicitly enabled")

	v.Set("mst.enabled", false)
	cfg, err = FromViper(v)
	require.NoError(t, err)
	require.False(t, cfg.Enabled)
}

func TestEnabledRequiresCoreSettings(t *testing.T) {
	v := viper.New()
	v.Set("mst.enabled", true)
	_, err := FromViper(v)
	require.ErrorContains(t, err, "outboxPath")

	v.Set("mst.outboxPath", "/var/mst")
	_, err = FromViper(v)
	require.ErrorContains(t, err, "rpcURL")
}

func TestFullConfig(t *testing.T) {
	// core.yaml carries only peer-local operational knobs now.
	v := viper.New()
	v.Set("mst.enabled", true)
	v.Set("mst.outboxPath", "/var/mst")
	v.Set("mst.channels", []string{"mychannel"})
	v.Set("mst.defaultStartBlock", 5)
	v.Set("mst.evm.rpcURL", "http://127.0.0.1:8545")
	v.Set("mst.evm.insecureSkipTLSVerify", true)
	v.Set("mst.evm.minBalanceGwei", 500000)
	v.Set("mst.sender.workers", 8)
	v.Set("mst.writeback.mspID", "Org1MSP")
	v.Set("mst.writeback.certPath", "/etc/cert.pem")
	v.Set("mst.writeback.keyPath", "/etc/key.pem")

	cfg, err := FromViper(v)
	require.NoError(t, err)
	require.True(t, cfg.Enabled)
	require.True(t, cfg.channelAllowed("mychannel"))
	require.False(t, cfg.channelAllowed("otherchannel"))
	require.Equal(t, uint64(500000), cfg.EVM.MinBalanceGwei)
	require.True(t, cfg.EVM.InsecureSkipTLSVerify)

	// The anchoring policy is channel-governed: the per-channel builders take
	// capture scope, batch strategy, and confirmations from the channel config,
	// keeping only the peer-local knobs from core.yaml.
	mst := &channelconfig.MSTAnchorConfig{
		CaptureMode:       "all",
		IncludeChaincodes: []string{"assets"},
		ExcludeChaincodes: []string{"other"},
		BatchStrategy:     "merkle",
		Confirmations:     3,
		CadenceMode:       "batch",
		CadenceN:          10,
		CadenceMaxWait:    "30s",
	}

	sc := cfg.SenderConfigFor(mst)
	require.Equal(t, 8, sc.Workers)                                // peer-local
	require.Equal(t, sender.CadenceMode("batch"), sc.Cadence.Mode) // channel
	require.Equal(t, 10, sc.Cadence.N)                             // channel
	require.Equal(t, 30*time.Second, sc.Cadence.MaxWait)           // channel
	require.Equal(t, uint64(3), sc.Confirmations)                  // channel
	require.Equal(t, sender.BatchStrategy("merkle"), sc.Strategy)  // channel

	cc := cfg.CaptureConfigFor(mst)
	require.Equal(t, uint64(5), cc.DefaultStartBlock)          // peer-local
	require.Equal(t, capture.ModeAll, cc.Mode)                 // channel
	require.Equal(t, []string{"assets"}, cc.IncludeChaincodes) // channel
	// echo-loop guard: the mst system chaincode is always excluded, alongside
	// the channel's own excludes.
	require.Contains(t, cc.ExcludeChaincodes, mstscc.Name)
	require.Contains(t, cc.ExcludeChaincodes, "other")
}

func TestEVMKeyFromEnvOnly(t *testing.T) {
	v := viper.New()
	v.Set("mst.enabled", true)
	v.Set("mst.outboxPath", "/var/mst")
	v.Set("mst.evm.rpcURL", "http://127.0.0.1:8545")
	cfg, err := FromViper(v)
	require.NoError(t, err)

	t.Setenv(EnvRelayerKey, "")
	_, err = cfg.EVMConfig()
	require.ErrorContains(t, err, EnvRelayerKey)

	t.Setenv(EnvRelayerKey, "aa")
	ec, err := cfg.EVMConfig()
	require.NoError(t, err)
	require.Equal(t, "aa", ec.PrivateKeyHex)
	require.False(t, ec.InsecureSkipTLSVerify)

	v.Set("mst.evm.insecureSkipTLSVerify", true)
	cfg, err = FromViper(v)
	require.NoError(t, err)
	ec, err = cfg.EVMConfig()
	require.NoError(t, err)
	require.True(t, ec.InsecureSkipTLSVerify)
}

func TestChannelAllowedEmptyMeansAll(t *testing.T) {
	c := &Config{}
	require.True(t, c.channelAllowed("anything"))
}

func TestOutboxFollowsPeerStateDatabase(t *testing.T) {
	base := func() *viper.Viper {
		v := viper.New()
		v.Set("mst.enabled", true)
		v.Set("mst.outboxPath", "/var/mst")
		v.Set("mst.evm.rpcURL", "http://127.0.0.1:8545")
		return v
	}

	// Default (goleveldb, or unset): embedded LevelDB.
	cfg, err := FromViper(base())
	require.NoError(t, err)
	require.Equal(t, "leveldb", cfg.Outbox.Backend)

	// Peer on CouchDB: outbox follows, reusing the peer's connection config.
	v := base()
	v.Set("ledger.state.stateDatabase", "CouchDB")
	v.Set("ledger.state.couchDBConfig.couchDBAddress", "127.0.0.1:5984")
	v.Set("ledger.state.couchDBConfig.username", "admin")
	v.Set("ledger.state.couchDBConfig.password", "adminpw")
	cfg, err = FromViper(v)
	require.NoError(t, err)
	require.Equal(t, "couchdb", cfg.Outbox.Backend)
	require.Equal(t, "127.0.0.1:5984", cfg.Outbox.CouchDB.Address)
	require.Equal(t, "admin", cfg.Outbox.CouchDB.Username)
	require.Equal(t, "adminpw", cfg.Outbox.CouchDB.Password)

	// mst.outbox.couchDB.* overrides win over the peer's settings.
	v.Set("mst.outbox.couchDB.address", "couch.example.com:5984")
	v.Set("mst.outbox.couchDB.username", "mst")
	cfg, err = FromViper(v)
	require.NoError(t, err)
	require.Equal(t, "couch.example.com:5984", cfg.Outbox.CouchDB.Address)
	require.Equal(t, "mst", cfg.Outbox.CouchDB.Username)
	require.Equal(t, "adminpw", cfg.Outbox.CouchDB.Password, "unset override falls back to peer config")

	// CouchDB state database without any address is a hard error.
	v = base()
	v.Set("ledger.state.stateDatabase", "CouchDB")
	_, err = FromViper(v)
	require.ErrorContains(t, err, "couchDB address")
}

func TestCouchDatabaseName(t *testing.T) {
	require.Equal(t, "mst_outbox_mychannel", couchDatabaseName("mychannel"))
	require.Equal(t, "mst_outbox_my_channel_v2", couchDatabaseName("my.channel.v2"))
}
