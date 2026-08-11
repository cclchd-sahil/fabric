/*
Copyright the MST integration contributors.
SPDX-License-Identifier: Apache-2.0
*/

package mst

import (
	"strings"
	"testing"

	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestNormalizeTxID(t *testing.T) {
	id, err := normalizeTxID("  " + strings.ToUpper(testTxID) + "  ")
	require.NoError(t, err)
	require.Equal(t, testTxID, id, "trimmed and lower-cased")

	_, err = normalizeTxID("abc")
	require.Error(t, err)
	require.Contains(t, err.Error(), "64 hex")
}

func TestRequireChannel(t *testing.T) {
	t.Cleanup(resetFlags)
	channelID = ""
	require.Error(t, requireChannel())
	channelID = "mychannel"
	require.NoError(t, requireChannel())
}

func TestEvmConfigForResolvesRPC(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
		resetFlags()
	})
	mstCfg := &channelconfig.MSTAnchorConfig{ContractAddress: "0x1234567890abcdef1234567890abcdef12345678", ChainID: 1337}

	// No RPC anywhere → error.
	viper.Reset()
	rpcOverride = ""
	_, err := evmConfigFor(mstCfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "RPC")

	// core.yaml value is used.
	viper.Set("mst.evm.rpcURL", "http://core:8545")
	cfg, err := evmConfigFor(mstCfg)
	require.NoError(t, err)
	require.Equal(t, "http://core:8545", cfg.RPCURL)
	require.Equal(t, mstCfg.ContractAddress, cfg.ContractAddress)
	require.Equal(t, mstCfg.ChainID, cfg.ChainID)
	require.False(t, cfg.InsecureSkipTLSVerify)
	require.NotEmpty(t, cfg.PrivateKeyHex, "a dummy read key is set")

	viper.Set("mst.evm.insecureSkipTLSVerify", true)
	cfg, err = evmConfigFor(mstCfg)
	require.NoError(t, err)
	require.True(t, cfg.InsecureSkipTLSVerify)

	// --rpc flag wins over core.yaml.
	rpcOverride = "http://flag:9545"
	cfg, err = evmConfigFor(mstCfg)
	require.NoError(t, err)
	require.Equal(t, "http://flag:9545", cfg.RPCURL)
}

func TestCadenceSummary(t *testing.T) {
	require.Equal(t, "per-tx", cadenceSummary(&channelconfig.MSTAnchorConfig{}))
	require.Equal(t, "batch (n=10, maxWait=30s)", cadenceSummary(&channelconfig.MSTAnchorConfig{CadenceMode: "batch", CadenceN: 10, CadenceMaxWait: "30s"}))
	require.Equal(t, "interval (1m0s)", cadenceSummary(&channelconfig.MSTAnchorConfig{CadenceMode: "interval", CadenceInterval: "1m0s"}))
	require.Contains(t, cadenceSummary(&channelconfig.MSTAnchorConfig{CadenceMode: "cron", CadenceCron: "0 * * * *"}), "cron")
}

func TestOrDefault(t *testing.T) {
	require.Equal(t, "opt-in (default)", orDefault("", "opt-in"))
	require.Equal(t, "all", orDefault("all", "opt-in"))
}

func TestRenderMetrics(t *testing.T) {
	sample := strings.Join([]string{
		"# HELP mst_outbox_entries entries",
		"# TYPE mst_outbox_entries gauge",
		"# channel mychannel",
		`mst_outbox_entries{status="PENDING"} 0`,
		`mst_outbox_entries{status="DONE"} 42`,
		"mst_outbox_oldest_active_age_seconds 0",
		"# relayer account",
		"mst_relayer_balance_gwei 1000000",
	}, "\n")

	var b strings.Builder
	renderMetrics(&b, sample)
	out := b.String()
	require.Contains(t, out, "channel mychannel")
	require.Contains(t, out, `mst_outbox_entries{status="DONE"} 42`)
	require.Contains(t, out, "relayer account")
	require.Contains(t, out, "mst_relayer_balance_gwei 1000000")
	// HELP/TYPE comment lines are filtered out.
	require.NotContains(t, out, "# HELP")
	require.NotContains(t, out, "# TYPE")
}
