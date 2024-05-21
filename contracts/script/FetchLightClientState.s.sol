// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import {Script, console} from "forge-std/Script.sol";
import { NovaDecider } from "../src/BTCLightClientNovaVerifier.sol";
import { BTCLightClient } from "../src/BTCLightClient.sol";
import "forge-std/console.sol";

contract FetchLightClientState is Script {

    BTCLightClient btcLightClient = BTCLightClient(0xB48A9Ef8F906f5C8CCF6593889aa26Cf3Af41846);

    function run() public view {
        console.log("Blocks verified: ", btcLightClient.blocksVerified());
        console.log("Start block: ", btcLightClient.startBlock(0), btcLightClient.startBlock(1));
        console.log("Current block tip: ", btcLightClient.currentBlockTip(0), btcLightClient.currentBlockTip(1));

    }

}
