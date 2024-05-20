#!/bin/bash
sudo apt-get update
sudo apt install build-essential clang tmux -y
curl https://sh.rustup.rs -sSf | sh -s -- -y
. "$HOME/.cargo/env"
# add solc bin in /usr/local/bin (!bin is for linux x64 arch!)
wget https://github.com/ethereum/solidity/releases/download/v0.8.25/solc-static-linux
sudo mv solc-static-linux /usr/local/bin/solc