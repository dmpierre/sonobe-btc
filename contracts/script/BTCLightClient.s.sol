// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import {Script, console} from "forge-std/Script.sol";
import { NovaDecider } from "../src/BTCLightClientNovaVerifier.sol";

contract DeployAndVerify is Script {

    NovaDecider decider;

    function setUp() public {
        decider = new NovaDecider();
    }

    function run() public {

        vm.broadcast();
    }
}
