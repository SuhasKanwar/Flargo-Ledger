// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Script } from "forge-std/Script.sol";
import { FlargoLedger } from "../src/FlargoLedger.sol";

contract FlargoLedgerScript is Script {
    FlargoLedger public flargoLedger;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        flargoLedger = new FlargoLedger();

        vm.stopBroadcast();
    }
}