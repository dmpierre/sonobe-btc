#!/bin/bash
# running on m7i.metal-24xl instance
# run with `source ./setup-machine.sh`
sudo apt-get update
sudo apt install build-essential clang tmux -y
curl https://sh.rustup.rs -sSf | sh -s -- -y
. "$HOME/.cargo/env"
git clone https://github.com/dmpierre/folding-schemes-light-btc.git