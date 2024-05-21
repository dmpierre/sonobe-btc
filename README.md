# Sonobe BTC

<p align="center">
  <img src="https://github.com/dmpierre/sonobe-btc/assets/23149200/782e7140-cc8e-4a9c-8a31-327a0ae84a5b" width="30%" height="30%" />
</p>

[Transaction trustlessly verifying 100k bitcoin blocks on Optimism](https://optimistic.etherscan.io/tx/0x1fc40181d6be767985aa13d8a5219ce85ce4d63d6b0e02a4942a7accf6027e48)

This project is an implementation of an on-chain bitcoin light client, running with [sonobe](https://github.com/privacy-scaling-explorations/sonobe). Sonobe is a folding schemes library, built with arkworks and on-chain (evm) verification capability. This project leverages sonobe to build a trustless light client for bitcoin: we use [nova](https://eprint.iacr.org/2021/370) to verify bitcoin's proof of work over 100k blocks and verify the zkSNARK IVC proof on chain.

# Details

Running the light client has been relatively cheap. Small costs breakdown:
- 33h of compute on an aws ec2 c6i.4xlarge instance (16 cores, 32gb RAM) = 26,64 USD
- Contract deployment + verification on Optimism = 0,91 USD. Transaction details [here](https://optimistic.etherscan.io/address/0x83c2acbbcc5e223be030288b5e5afb0b80e96f3f).

Note that we deactivated sonobe's `light-test` feature when running proving. Be mindful if you are running `main.rs`: the repo's `Cargo.toml` has this feature activated.

# How to check the verified starting and current btc block tip on chain

We fetch the starting and current block tip within the `FetchLightClientState.s.sol` `forge` script. We obtain two hashes, each sliced in two 16 bytes integers. Run a quick check with python:

```python
>>> block_0, block_1 = hex(148720607008399139643368409540449269583)[2:], hex(195554949353584141652985335246347042816)[2:]
>>> block_0 + block_1
'6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000'
>>> current_block_tip_0, current_block_tip_1 = hex(9165458411239663043281073488483627218)[2:], hex(160611593144357295069611026580695416832)[2:]
>>> current_block_tip_0 + current_block_tip_1
'6e533fd1ada86391f3f6c343204b0d278d4aaec1c0b20aa27ba030000000000'
```

See block 0 hash [here](https://btcscan.org/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f) and block 100k hash [here](https://btcscan.org/block/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506).