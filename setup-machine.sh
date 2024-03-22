#!/bin/bash
# script for setting up a new machine to generate light client btc proofs 
sudo apt-get update
curl https://sh.rustup.rs -sSf | sh -s -- -y # install rust, defaulting to yes
. "$HOME/.cargo/env"

