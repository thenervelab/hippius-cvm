# register-miner — permissionless on-chain miner onboarding (§23, PR-3)

Binds a miner's Ed25519 **node identity** to an on-chain account via
`pallet-compute-scoring::register_child`, so the miner becomes `Active`
and is admitted by the Edge's permissionless auth (PR-2) and ranked by
the §23 scheduler. **No operator certificate** — the trust anchor is
the chain (`docs/design/permissionless-miner-auth.md`).

## Trust split

Two boxes, two secrets, neither crosses to the other:

| Box | Holds | Produces |
|---|---|---|
| **Miner** | the identity key (no funds) | the `node_sig` (via the agent) |
| **Operator** | the family key (no node key) | the signed `register_child` extrinsic |

## Prerequisites

- The **family** account is registered (per the runtime's
  `FamilyRegistry` / `pallet_registration`) and funded enough to reserve
  the child deposit (`BaseChildDeposit`, unless free slots remain or
  lockup is disabled).
- The family has authorised the **child as a `pallet_proxy` delegate**.
  `register_child` gates on `ProxyVerifier::can_register_child`, so
  without it the extrinsic fails `ProxyVerificationFailed` — after the
  `node_sig` has already been produced, which is a confusing place to
  discover a missing prerequisite. See "Authorise the child" below.
- Both the family AND the child accounts must **exist on-chain**
  (`providers > 0` — an existential-deposit transfer is enough). A
  brand-new account is rejected at transaction *validity* with
  `1010: Inability to pay some fees`, even though `register_child`
  itself is `Pays::No`: the fee is waived, the account's existence is
  not.
- `pip install substrate-interface` on the operator workstation.

## Authorise the child (`pallet_proxy`)

```bash
# From the FAMILY account:
proxy.addProxy(delegate = <child>, proxy_type = NonTransfer, delay = 0)
```

- **`NonTransfer` is sufficient**, and preferable to `Any`:
  `can_register_child` checks only that the child appears as a delegate —
  it does not filter on proxy type — and the runtime's `NonTransfer`
  filter is a blacklist that does not cover `ComputeScoring` calls. The
  delegation therefore permits the registration without exposing the
  family's funds.
- **`delay` must be 0.** A non-zero delay forces the announce-then-wait
  path, which this flow does not use.
- The gate is checked **only inside `register_child`** — nothing reads it
  afterwards. So the proxy can be removed with `proxy.removeProxy(...)`
  as soon as the registration is in a block; the child stays registered.
- On this runtime `ProxyDepositBase` and `ProxyDepositFactor` are both
  `deposit(0, 0)` = 0, so `addProxy` reserves nothing — only the ordinary
  transaction fee applies.

## Flow

```bash
# (0) Operator: get the 0x-hex AccountIds the agent wants (it takes raw
#     hex, not SS58, to stay dependency-light).
python register_miner.py account-hex <family_ss58>   # → 0x<family_hex>
python register_miner.py account-hex <child_ss58>    # → 0x<child_hex>

# (1) On the MINER box (holds the identity key): sign the authorisation.
#     --nonce is the on-chain NodeIdNonce for this node_id (0 first time).
hippius-miner-agent sign-registration \
    --family 0x<family_hex> \
    --child  0x<child_hex> \
    --nonce  0
# → {"node_id":"...","node_sig":"...","nonce":0}   (copy this JSON)

# (2) On the OPERATOR workstation (holds the family key): submit.
python register_miner.py submit \
    --rpc wss://<HIPPIUS_CHAIN_RPC_HOST> \
    --family <family_ss58> \
    --family-suri @~/.config/hippius/family-mnemonic \
    --child  <child_ss58> \
    --node-auth '{"node_id":"...","node_sig":"...","nonce":0}'
```

`--node-auth` accepts the inline JSON, `@path`, or `-` (stdin). The
script cross-checks that `--family` matches `--family-suri`'s account
(the `node_sig` is bound to a specific family) and fails loudly on a
mismatch rather than letting the chain reject it opaquely.

Use `--dry-run` to compose + print the call without submitting.

## After registration

The miner's `node_id` appears in `NodeIdToChild` with the implicit
`Active` status. Within one Edge `EDGE_REGISTRY_REFRESH_SECS` cycle the
gateway admits its self-signed identity cert (PR-1/PR-2); the §23
scheduler ranks it once the validator scores it (`EpochWeights`).
