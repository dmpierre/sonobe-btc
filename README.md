# Sonobe BTC

<p align="center">
  <img src="" width="30%" height="30%" />
</p>

[Transaction trustlessly verifying 100k bitcoin blocks on Optimism](https://optimistic.etherscan.io/tx/0x1fc40181d6be767985aa13d8a5219ce85ce4d63d6b0e02a4942a7accf6027e48)

This project is an implementation of an on-chain bitcoin light client, running with [sonobe](https://github.com/privacy-scaling-explorations/sonobe). Sonobe is a folding schemes library, built with arkworks and with on-chain verification capability. This project leverages sonobe to build a trustless light client for bitcoin: we use [nova](https://eprint.iacr.org/2021/370) to verify bitcoin's proof of work over 100k blocks and verify the zkSNARK IVC proof on chain.

# Details

Running the light client has been relatively cheap. Small costs breakdown:
- 33h of compute on an aws ec2 c6i.4xlarge instance = 26,64 USD
- Contract deployment + verification on Optimism = 0,91 USD. Transaction details [here](https://optimistic.etherscan.io/address/0x83c2acbbcc5e223be030288b5e5afb0b80e96f3f).