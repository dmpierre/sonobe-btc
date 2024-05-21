// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;
import {NovaDecider} from "./BTCLightClientNovaVerifier.sol";

contract BTCLightClient {

    uint256 public blocksVerified; // Number of blocks verified
    uint256[2] public startBlock; // First verified pow block
    uint256[2] public currentBlockTip; // Tip of the pow - last verified block

    NovaDecider decider;

    constructor(address deciderAdress) {
        decider = NovaDecider(deciderAdress);
    }

    function setDecider(address deciderAdress) public {
        decider = NovaDecider(deciderAdress);
    }


    function setBlocksVerified( 
        uint256[7] calldata i_z0_zi,
        uint256[4] calldata U_i_cmW_U_i_cmE,
        uint256[3] calldata U_i_u_u_i_u_r,
        uint256[4] calldata U_i_x_u_i_cmW,
        uint256[4] calldata u_i_x_cmT,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[4] calldata challenge_W_challenge_E_kzg_evals,
        uint256[2][2] calldata kzg_proof
) public {
        require(decider.verifyNovaProof(i_z0_zi, U_i_cmW_U_i_cmE, U_i_u_u_i_u_r, U_i_x_u_i_cmW, u_i_x_cmT, pA, pB, pC, challenge_W_challenge_E_kzg_evals, kzg_proof), "Proof: verification failed");
        if (blocksVerified > 0) {
            // we require to start from the last verified block
            require(i_z0_zi[2] == currentBlockTip[0] && i_z0_zi[3] == currentBlockTip[1], "Block: start block does not match current block tip");
        }
        blocksVerified = i_z0_zi[0];
        startBlock = [i_z0_zi[2], i_z0_zi[3]];
        currentBlockTip = [i_z0_zi[5], i_z0_zi[6]];
    }

}
