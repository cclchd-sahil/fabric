# MST Anchoring — Setup Guide (Phase 1.5)

Operator-oriented, step-by-step setup for the **new approach**: per-channel
contracts, channel-config governance, and the built-in `mstscc` system chaincode.
For the design rationale see [PHASE-1.5.md](PHASE-1.5.md) and
[KNOWLEDGE_TRANSFER.md](KNOWLEDGE_TRANSFER.md); for the local demo walk see
[deploy/README.md](deploy/README.md); for the `peer mst` commands see
[CLI.md](CLI.md).

> **Legacy note.** The Phase 1 sidecar (`mst-relayd`, shared contract, `mst-anchor-status`
> user chaincode) is still supported for existing channels — see the Phase 1 SETUP in
> git history. This guide is the **embedded, channel-governed** path. New channels use it.

---

## 0. What you are deploying

| Piece                                           | Where                                | Purpose                                                                     |
| ----------------------------------------------- | ------------------------------------ | --------------------------------------------------------------------------- |
| `MSTAnchor` contract **behind a proxy**         | MST chain (EVM), **one per channel** | public record of commitments / batch roots at a stable, upgradeable address |
| `V2_5_MSTANCHOR` capability + `MSTAnchor` value | channel configuration                | all-org-agreed enablement + anchoring policy                                |
| `mstscc` system chaincode                       | built into the peer (opt-in)         | write-back target ("is tx X anchored?"), peer-role gated                    |
| business chaincodes + `proofhelper`             | your channels                        | opt-in: emit `MSTProofRequest` per tx (not needed in capture mode `all`)    |
| the embedded relayer                            | inside the MST-enabled peer          | capture → outbox → anchor → write-back                                      |
| `peer mst` / `mst-verify`                       | anywhere                             | operator helpers / independent verification                                 |

## 1. Prerequisites

- Go 1.24+, Node 22+ (contract toolchain), a Fabric 2.5 network built from **this
  fork's peer binary** (the embedded path needs it; a vanilla peer will refuse a
  channel that enables the capability).
- **NodeOUs enabled** on every participating org's MSP (`config.yaml` with
  `NodeOUs.Enable: true`) — the write-back peer-role gate fails closed without it.
- **The anchoring org's channel `Writers` policy must admit the peer role** —
  e.g. `Rule: "OR('Org1MSP.admin','Org1MSP.client','Org1MSP.peer')"`. The
  write-back is signed by a peer-role identity (to pass the mstscc gate), but the
  orderer independently evaluates the broadcast against `Writers`, and the default
  NodeOUs `Writers` = `OR('Org.admin','Org.client')` **excludes** peer. Without
  the peer role in `Writers`, endorsement succeeds but the orderer rejects the
  transaction with `FORBIDDEN` (`peer mst preflight` reports this on its `writers`
  line, and the peer logs a startup warning).
- An MST (EVM) endpoint: any JSON-RPC URL. For dev: `cd mst/anchor-contracts && npm install && npx hardhat node`.
- A funded EVM account for the relayer (it pays gas). Keep its key OUT of files —
  read from the `MST_RELAYER_KEY` env var only.

## 2. Deploy the anchor contract — once per channel, behind a proxy

Each channel gets its **own** contract; the proxy address is what the channel config
points at (stable across upgrades).

```bash
cd mst/anchor-contracts
npm install && npm run build
# optional allowlist: ANCHOR_ALLOWLIST_ENABLED=true ANCHOR_RELAYERS=0xRelayerAddr
MST_RPC_URL=https://<mst-rpc> MST_CHAIN_ID=<id> MST_RELAYER_KEY=<hex> npm run deploy:mst
# -> prints the PROXY address (record it), plus the implementation + proxy-admin addresses
```

The `deployments/<network>.json` record has `address` (the proxy — use this),
`implementation`, and `proxyAdmin`. **The ProxyAdmin (deployer key) can upgrade the
implementation and thereby alter anchors** — for production, transfer it to a
timelock+multisig (see [anchor-contracts/README.md](anchor-contracts/README.md)). To
upgrade later without changing the address: `NEW_CONTRACT=MSTAnchor npm run upgrade:mst`.

## 3. Turn anchoring on in the channel configuration

Anchoring is a channel-config value agreed by all orgs — not a per-peer flag. At
channel creation, declare it in `configtx.yaml` (both the capability and the value):

```yaml
Capabilities:
  Application: &ApplicationCapabilities
    V2_5: true
    V2_5_MSTANCHOR: true # REQUIRED for the MSTAnchor value below

Application:
  Capabilities:
    <<: *ApplicationCapabilities
  MSTAnchor:
    Enabled: true
    ContractAddress: "0xYourPerChannelProxyAddress…" # the PROXY from step 2
    ChainID: 1337
    CaptureMode: opt-in # or "all"
    # IncludeChaincodes: [myapp]  # "all"-mode scope
    # ExcludeChaincodes: []
    BatchStrategy: individual # or "merkle"
    Confirmations: 1
    # Flush cadence: per-tx | batch | interval | cron
    CadenceMode: per-tx
```

For an **existing** channel, make the same change as a channel-config update (add the
`V2_5_MSTANCHOR` capability and the `MSTAnchor` value), signed under the Application
group's mod policy (all-org agreement). The value is rejected if the capability is
absent, and rejected at apply time if the contract address is malformed/zero or the
cadence is inconsistent. **Run `peer mst preflight` first** (step 6).

Governed policy fields (`CaptureMode`, `Include`/`ExcludeChaincodes`, `BatchStrategy`,
`Confirmations`, `Cadence*`) live here, not in `core.yaml`, so every peer anchors
identically; each is optional and falls back to a built-in default. A later change to
any of them is **applied live** (the peer hot-reloads the channel's pipeline).

## 4. Opt the peer into the system chaincode + the embedded relayer

Build the peer from THIS fork and enable `mstscc` + the `mst:` section in `core.yaml`
(full commented reference in `sampleconfig/core.yaml`):

```yaml
chaincode:
    system:
        mstscc: enable                  # the built-in write-back SCC

mst:
    enabled: true                       # default false = vanilla peer
    outboxPath: /var/hyperledger/production/mst-outbox
    channels: []                        # empty = every joined channel that enabled MST
    evm:
        rpcURL: https://<mst-rpc>       # peer-local: the one chain this peer anchors to
      insecureSkipTLSVerify: false    # DEV/TEST ONLY for self-signed/unknown CAs
        minBalanceGwei: 100000000       # alert threshold; 0 = off
    sender:
        workers: 4
    writeback:                          # the peer's OWN node signing identity (NodeOUs peer)
        mspID: Org1MSP
        certPath: /etc/hyperledger/msp/signcerts/peer-cert.pem
        keyPath: /etc/hyperledger/msp/keystore/peer-key.pem
    metricsAddr: ":9464"
```

Note what is **not** here: contract address, chain-id policy, capture mode, batch
strategy, confirmations, and cadence are all channel-governed (step 3). `core.yaml`
keeps only peer-local plumbing. `ChainID` from the channel config is validated against
the chain the peer's RPC reports; a mismatch means the peer refuses that channel.
If your HTTPS/WSS RPC endpoint uses a private/self-signed CA, prefer installing that
CA in the peer trust store. As a temporary workaround in non-production environments,
set `mst.evm.insecureSkipTLSVerify: true`.

Then start it:

```bash
MST_RELAYER_KEY=<hex> peer node start
```

Requirements: `peer.gateway.enabled` (default true) for write-back; the outbox backend
auto-follows `ledger.state.stateDatabase` (CouchDB peers keep it on their CouchDB
server as `mst_outbox_<channel>` databases). Misconfiguration fails startup with a
clear error; MST outages at runtime never affect the peer. If the write-back org lacks
NodeOUs, the peer logs a loud startup warning (write-backs would be rejected).

## 5. Opt in a business transaction (or use capture mode `all`)

```go
// in your chaincode, per proof-enabled tx:
proofhelper.New().AddString("asset_id", id).AddInt64("value", v).Emit(ctx.GetStub())
```

Skip this entirely if the channel config sets `CaptureMode: all` (every valid tx is
anchored; non-opted ones get the well-known empty-payload commitment).

## 6. Verify the config before and after applying it

```bash
# BEFORE applying a channel-config update: check it against the live chain.
peer mst preflight -C mychannel --rpc http://<mst-rpc>
#   [PASS] enabled / rpc endpoint / chain id / contract / nodeous
#   exits non-zero if any check FAILs

# AFTER anchoring runs: confirm the pipeline and a specific tx.
peer mst pipeline                                  # relayer + per-channel outbox metrics
peer mst status <txid> -C mychannel                # the anchor-status ledger fact (via mstscc)
peer mst onchain <txid> -C mychannel --rpc <rpc>   # read the anchor straight from the contract

# independent verification (the point of the whole system):
peer mst verify <txid> -C mychannel --rpc <rpc>    # exit 0 = MATCH
# or the standalone tool with explicit inputs:
mst-verify --tx-id <txid> --channel mychannel --chaincode <cc> \
  --block <n> --timestamp <channel-header-ts> --payload payload.json \
  --rpc <mst-rpc> --contract <proxy-address>
```

See [CLI.md](CLI.md) for the full `peer mst` surface (`is-anchored`, `list`, `count`,
`channel-config`, `relayer add/remove`).

## 7. Choosing capture, batching, and cadence (all channel-governed)

| Setting         | Options                                                                                   | Notes                                                                                                                                                              |
| --------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `CaptureMode`   | `opt-in` (default) / `all`                                                                | `all` anchors EVERY valid tx (non-opted ones with the empty-payload hash — existence proof); scope with `IncludeChaincodes`; gas scales with traffic, use batching |
| `BatchStrategy` | `individual` (default) / `merkle`                                                         | individual: one record per tx, flushes share one EVM tx. merkle: one root per flush; verifiers need inclusion proofs                                               |
| `CadenceMode`   | `per-tx` / `batch` (+`CadenceN`, `CadenceMaxWait`) / `interval` / `cron` (+`CadenceCron`) | WHEN flushes happen; independent of strategy                                                                                                                       |

These are set in the channel config (step 3), so all peers agree; changing one is a
channel-config update that hot-reloads the pipeline. Sane pairings: low-latency
compliance → `opt-in` + `individual` + `per-tx`; high-volume audit trail → `all` +
`merkle` + `cron "0 * * * *"`.

## 8. Operate

- **Metrics** (`metricsAddr`, or `peer mst pipeline`): `mst_outbox_entries{status=…}`,
  `mst_outbox_oldest_active_age_seconds`, `mst_outbox_quarantined_total`,
  `mst_relayer_balance_gwei`. Alert on growing PENDING/oldest-age and on the balance
  gauge.
- **Funding**: set `minBalanceGwei`; the relayer logs an error each minute while
  underfunded and recovers once topped up.
- **Crash/outage recovery is automatic**: durable outbox + idempotent contract; on
  restart the relayer reconciles in-flight submissions and resumes from its checkpoint.
- **Live config changes** take effect automatically (pipeline hot-reload); disabling
  MST in the channel config stops that channel's pipeline. Peer-local `core.yaml`
  changes (workers, outbox path) still need a peer restart.
- **The one log line needing a human**: `anchor exists with mismatched commitment` —
  an on-chain anchor disagrees with local capture; never retried, must be investigated.
- **Contract upgrades**: `npm run upgrade:*` keeps the same address; guard the admin key.

## 9. Troubleshooting

| Symptom                                                                     | Likely cause                                                                                                                                                                                |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A peer refuses to join the channel / rejects the config                     | it's a vanilla binary (no `V2_5_MSTANCHOR` capability) or doesn't run `mstscc` — rebuild from this fork and enable the SCC                                                                  |
| Config-update rejected at apply time                                        | `MSTAnchor` value without the capability, or a malformed/zero contract address / inconsistent cadence — run `peer mst preflight`                                                            |
| Anchors land on MST but no ledger status; write-backs rejected              | the write-back org lacks NodeOUs (peer-role gate fails closed), or `mst.writeback.*` is a client cert not the peer signcert — check the startup warning / `peer mst preflight` nodeous line |
| Write-back endorses but fails with `FORBIDDEN ... Writers` from the orderer | the channel `Writers` policy excludes the peer role — add it, e.g. `OR('Org.admin','Org.client','Org.peer')`; `peer mst preflight` flags this on its `writers` line                         |
| Peer refuses to anchor a channel                                            | its declared `ChainID` doesn't match the peer's RPC chain — point `mst.evm.rpcURL` at the right node                                                                                        |
| Peer refuses to start with `mstanchor:` error                               | incomplete `mst:` config or missing `MST_RELAYER_KEY` — intentional fail-fast                                                                                                               |
| Entries stuck PENDING, balance gauge low/absent                             | relayer account out of gas, or MST RPC unreachable (backoff retries automatically)                                                                                                          |
| Quarantine count rising                                                     | a chaincode emits malformed `MSTProofRequest` payloads — inspect the `q/` records; fix the emitter (use `proofhelper`)                                                                      |
