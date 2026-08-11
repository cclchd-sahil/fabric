/*
Copyright the MST integration contributors.
SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"

	"github.com/hyperledger/fabric/core/peer"
	"github.com/hyperledger/fabric/core/scc/mstscc"
	"github.com/hyperledger/fabric/internal/pkg/gateway"
	"github.com/hyperledger/fabric/internal/pkg/mstanchor"
	"github.com/spf13/viper"

	"github.com/hansrajrami/fabric/mst/relay/sender"
)

// mstGatewayServer and mstEndorserServer are set by serve() as the peer
// wires up its gateway and endorser; the MST write-back invokes them
// in-process (no loopback network hop). The endorser handles endorsement
// (it runs the built-in mstscc), the gateway handles ordering + commit.
var (
	mstGatewayServer  *gateway.Server
	mstEndorserServer mstanchor.EndorserProcessor
)

// startMSTAnchoring boots the embedded MST anchoring pipeline when
// core.yaml enables it (mst.enabled, default false). Returns nil when
// disabled — the peer then behaves exactly like vanilla Fabric.
func startMSTAnchoring(peerInstance *peer.Peer) (*mstanchor.Service, error) {
	cfg, err := mstanchor.FromViper(viper.GetViper())
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, nil
	}

	// Phase 1.5 write-back target is the built-in mst system chaincode, not a
	// deployed user chaincode: anchor status becomes a consensus-backed ledger
	// fact, active on any channel whose config enables MST anchoring. The
	// write-back submits RecordAnchor through the peer's embedded gateway,
	// signed with the relayer's Fabric identity (mst.writeback.*).
	var writeback sender.WriteBack
	if cfg.WriteBack.MSPID != "" {
		if mstGatewayServer == nil {
			return nil, fmt.Errorf("mst write-back requires the embedded gateway (peer.gateway.enabled) and discovery (peer.discovery.enabled)")
		}
		if mstEndorserServer == nil {
			return nil, fmt.Errorf("mst write-back requires the peer endorser to be initialized")
		}
		writeback, err = mstanchor.NewLoopbackWriteBack(
			mstEndorserServer,
			mstGatewayServer,
			mstscc.Name,
			cfg.WriteBack,
		)
		if err != nil {
			return nil, err
		}
	} else {
		logger.Warning("MST anchoring enabled without mst.writeback identity: anchors will not be recorded back on Fabric")
	}

	channels := func() []string {
		infos := peerInstance.GetChannelsInfo()
		ids := make([]string, 0, len(infos))
		for _, info := range infos {
			ids = append(ids, info.GetChannelId())
		}
		return ids
	}

	service := mstanchor.New(cfg, peerInstance, channels, writeback)
	if err := service.Start(); err != nil {
		return nil, err
	}
	return service, nil
}
