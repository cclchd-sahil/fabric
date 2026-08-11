/*
Copyright the MST integration contributors.
SPDX-License-Identifier: Apache-2.0
*/

// Package mst implements the `peer mst` command group: operator helpers that
// talk to the MST anchor-status system chaincode (mstscc), the channel's MST
// configuration, the per-channel MST contract, and the local relayer.
package mst

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang/protobuf/proto"
	cb "github.com/hyperledger/fabric-protos-go/common"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/core/scc/cscc"
	"github.com/hyperledger/fabric/core/scc/mstscc"
	"github.com/hyperledger/fabric/internal/peer/common"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/hansrajrami/fabric/mst/relay/evm"
)

var logger = flogging.MustGetLogger("cli.mst")

// dummyReadKey is a syntactically valid, well-known private key used only for
// read-only EVM calls (eth_call never signs). It is never used to send a
// transaction. Mirrors the read-only pattern in cmd/mst-verify.
const dummyReadKey = "0000000000000000000000000000000000000000000000000000000000000001"

// Cmd returns the `peer mst` command group.
func Cmd(cryptoProvider bccsp.BCCSP) *cobra.Command {
	mstCmd.AddCommand(statusCmd())
	mstCmd.AddCommand(isAnchoredCmd())
	mstCmd.AddCommand(listCmd())
	mstCmd.AddCommand(countCmd())
	mstCmd.AddCommand(channelConfigCmd(cryptoProvider))
	mstCmd.AddCommand(onchainCmd(cryptoProvider))
	mstCmd.AddCommand(preflightCmd(cryptoProvider))
	mstCmd.AddCommand(verifyCmd(cryptoProvider))
	mstCmd.AddCommand(pipelineCmd())
	mstCmd.AddCommand(relayerCmd(cryptoProvider))
	return mstCmd
}

var mstCmd = &cobra.Command{
	Use:   "mst",
	Short: "Interact with MST anchoring: status|is-anchored|list|count|channel-config|verify|onchain|preflight|pipeline|relayer",
	Long:  "Query the MST anchor-status system chaincode, inspect a channel's MST configuration, verify anchors, preflight a channel's config against the live chain, check the local relayer, and manage the per-channel contract's relayer allowlist.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		common.InitCmd(cmd, args)
	},
}

// Shared flag values.
var (
	channelID        string
	peerAddresses    []string
	tlsRootCertFiles []string
	rpcOverride      string
	listLimit        int
	jsonOutput       bool
)

var flags *pflag.FlagSet

func init() {
	resetFlags()
}

func resetFlags() {
	flags = &pflag.FlagSet{}
	flags.StringVarP(&channelID, "channelID", "C", "", "The channel to target")
	flags.StringSliceVarP(&peerAddresses, "peerAddresses", "", nil, "The addresses of the peers to connect to (default: the local peer)")
	flags.StringSliceVarP(&tlsRootCertFiles, "tlsRootCertFiles", "", nil, "The paths to the TLS root cert files of the peers to connect to (matched by position with --peerAddresses)")
	flags.StringVarP(&rpcOverride, "rpc", "", "", "Override the MST EVM RPC endpoint (default: mst.evm.rpcURL from core.yaml)")
	flags.IntVarP(&listLimit, "limit", "", 0, "Maximum number of records to list (0 = server default)")
	flags.BoolVarP(&jsonOutput, "json", "", false, "Emit raw JSON instead of human-readable output")
}

func attachFlags(cmd *cobra.Command, names []string) {
	cmdFlags := cmd.Flags()
	for _, name := range names {
		if flag := flags.Lookup(name); flag != nil {
			cmdFlags.AddFlag(flag)
		} else {
			logger.Fatalf("Could not find flag '%s' to attach to command '%s'", name, cmd.Name())
		}
	}
}

// clients bundles a signer and one endorser client for a single round trip.
type clients struct {
	signer   identity.SignerSerializer
	endorser pb.EndorserClient
}

// initClients builds a signer + endorser client, targeting the first
// --peerAddresses entry or, when none is given, the local peer from core.yaml.
func initClients() (*clients, error) {
	address, tlsFile := "", ""
	if len(peerAddresses) > 0 {
		address = peerAddresses[0]
		if len(tlsRootCertFiles) > 0 {
			tlsFile = tlsRootCertFiles[0]
		}
	}
	endorser, err := common.GetEndorserClientFnc(address, tlsFile)
	if err != nil {
		return nil, fmt.Errorf("getting endorser client: %w", err)
	}
	signer, err := common.GetDefaultSignerFnc()
	if err != nil {
		return nil, fmt.Errorf("getting default signer: %w", err)
	}
	return &clients{signer: signer, endorser: endorser}, nil
}

// requireChannel validates the -C flag.
func requireChannel() error {
	if channelID == "" {
		return fmt.Errorf("the required flag '-C/--channelID' was not specified")
	}
	return nil
}

// queryMSTSCC runs a read-only invocation of a mstscc function on the channel.
func (c *clients) queryMSTSCC(fn string, args ...string) ([]byte, error) {
	return c.queryCC(mstscc.Name, append([]string{fn}, args...)...)
}

// queryCC runs a read-only invocation of any chaincode (args[0] is the function
// name) and returns the response payload. It builds the proposal directly (the
// same pattern peer chaincode query uses) rather than going through the
// chaincode package's flag globals.
func (c *clients) queryCC(ccName string, args ...string) ([]byte, error) {
	ccArgs := make([][]byte, 0, len(args))
	for _, a := range args {
		ccArgs = append(ccArgs, []byte(a))
	}
	invocation := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			Type:        pb.ChaincodeSpec_GOLANG,
			ChaincodeId: &pb.ChaincodeID{Name: ccName},
			Input:       &pb.ChaincodeInput{Args: ccArgs},
		},
	}
	return c.processQuery(cb.HeaderType_ENDORSER_TRANSACTION, invocation)
}

// fetchMSTConfig reads the channel's MST configuration from its current config
// block, via cscc GetChannelConfig -> channelconfig.NewBundle. Returns an error
// when the channel has no MST configuration.
func (c *clients) fetchMSTConfig(cryptoProvider bccsp.BCCSP) (*channelconfig.MSTAnchorConfig, error) {
	mstCfg, _, err := c.fetchMSTConfigAndProto(cryptoProvider)
	return mstCfg, err
}

// fetchMSTConfigAndProto is fetchMSTConfig that additionally returns the raw
// channel config proto, for callers (e.g. preflight) that need to inspect other
// parts of the config such as the orgs' MSP NodeOUs settings.
func (c *clients) fetchMSTConfigAndProto(cryptoProvider bccsp.BCCSP) (*channelconfig.MSTAnchorConfig, *cb.Config, error) {
	invocation := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			Type:        pb.ChaincodeSpec_GOLANG,
			ChaincodeId: &pb.ChaincodeID{Name: "cscc"},
			Input:       &pb.ChaincodeInput{Args: [][]byte{[]byte(cscc.GetChannelConfig), []byte(channelID)}},
		},
	}
	payload, err := c.processQuery(cb.HeaderType_CONFIG, invocation)
	if err != nil {
		return nil, nil, err
	}
	config := &cb.Config{}
	if err := proto.Unmarshal(payload, config); err != nil {
		return nil, nil, fmt.Errorf("unmarshal channel config: %w", err)
	}
	bundle, err := channelconfig.NewBundle(channelID, config, cryptoProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("build channel config bundle: %w", err)
	}
	app, ok := bundle.ApplicationConfig()
	if !ok {
		return nil, nil, fmt.Errorf("channel %s has no application config", channelID)
	}
	mstCfg, ok := app.MSTAnchorConfig()
	if !ok {
		return nil, nil, fmt.Errorf("channel %s has no MST anchoring configuration", channelID)
	}
	return mstCfg, config, nil
}

// processQuery signs and sends a proposal to the endorser and returns the
// response payload, surfacing a non-success status as an error.
func (c *clients) processQuery(hdrType cb.HeaderType, invocation *pb.ChaincodeInvocationSpec) ([]byte, error) {
	creator, err := c.signer.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize identity: %w", err)
	}
	prop, _, err := protoutil.CreateProposalFromCIS(hdrType, channelID, invocation, creator)
	if err != nil {
		return nil, fmt.Errorf("create proposal: %w", err)
	}
	signedProp, err := protoutil.GetSignedProposal(prop, c.signer)
	if err != nil {
		return nil, fmt.Errorf("sign proposal: %w", err)
	}
	resp, err := c.endorser.ProcessProposal(context.Background(), signedProp)
	if err != nil {
		return nil, fmt.Errorf("process proposal: %w", err)
	}
	if resp == nil || resp.Response == nil {
		return nil, fmt.Errorf("nil proposal response")
	}
	if resp.Response.Status != int32(cb.Status_SUCCESS) {
		return nil, fmt.Errorf("query failed (%d): %s", resp.Response.Status, resp.Response.Message)
	}
	return resp.Response.Payload, nil
}

// evmConfigFor resolves the EVM RPC endpoint (flag or core.yaml) and builds a
// read-only evm.Config for the channel's contract. The key is a dummy — reads
// never sign.
func evmConfigFor(mstCfg *channelconfig.MSTAnchorConfig) (evm.Config, error) {
	rpc := rpcOverride
	if rpc == "" {
		rpc = viper.GetString("mst.evm.rpcURL")
	}
	if rpc == "" {
		return evm.Config{}, fmt.Errorf("no MST RPC endpoint: set --rpc or mst.evm.rpcURL")
	}
	return evm.Config{
		RPCURL:                rpc,
		ContractAddress:       mstCfg.ContractAddress,
		ChainID:               mstCfg.ChainID,
		InsecureSkipTLSVerify: viper.GetBool("mst.evm.insecureSkipTLSVerify"),
		PrivateKeyHex:         dummyReadKey,
	}, nil
}

// dialReadOnlyEVM dials the channel's MST contract for read-only calls.
func dialReadOnlyEVM(ctx context.Context, mstCfg *channelconfig.MSTAnchorConfig) (*evm.Client, error) {
	cfg, err := evmConfigFor(mstCfg)
	if err != nil {
		return nil, err
	}
	return evm.Dial(ctx, cfg)
}

// normalizeTxID lower-cases and validates a 64-hex Fabric tx id argument.
func normalizeTxID(arg string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(arg))
	if len(id) != 64 {
		return "", fmt.Errorf("fabric tx id must be 64 hex chars, got %d", len(id))
	}
	return id, nil
}
