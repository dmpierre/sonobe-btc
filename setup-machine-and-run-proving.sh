#!/bin/bash
# running on m7i.metal-24xl instance
# run with `source ./setup-machine-and-run-proving.sh`
sudo apt-get update
sudo apt install build-essential -y
curl https://sh.rustup.rs -sSf | sh -s -- -y
. "$HOME/.cargo/env"
git clone https://github.com/dmpierre/folding-schemes-light-btc.git
cd folding-schemes-light-btc && cargo run -r