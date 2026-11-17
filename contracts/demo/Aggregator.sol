// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Interfaces.sol";

// A registered ENTRY CONTRACT: it moves the owner's assets, splits one swap
// over several covered pools and records ONCE with the net amounts,
// reporting its caller as the owner. The pools see a registered entry
// contract as their caller and record nothing.
contract Aggregator {
    IAgency public immutable agency;

    event SplitSwap(address indexed owner, address tokenIn, uint256 amountIn,
                    address tokenOut, uint256 amountOut, uint256 legs);

    constructor(address _agency) { agency = IAgency(_agency); }

    function swapSplit(address tokenIn, address tokenOut,
        address[] calldata pools, uint256[] calldata amounts,
        uint256 minOut, RecArgs calldata rec) external returns (uint256 totalOut)
    {
        require(pools.length == amounts.length && pools.length != 0, "bad legs");
        RecArgs memory none;      // the pools do not record: empty arguments
        uint256 totalIn;
        for (uint256 k = 0; k < pools.length; k++) {
            (address legOut, ) = IPool(pools[k]).quote(tokenIn, amounts[k]);
            require(legOut == tokenOut, "pool does not trade this pair");
            require(IERC20Like(tokenIn).transferFrom(msg.sender, address(this), amounts[k]), "pull failed");
            require(IERC20Like(tokenIn).approve(pools[k], amounts[k]), "approve failed");
            totalOut += ICoveredPool(pools[k]).swap(tokenIn, amounts[k], 0, msg.sender, none);
            totalIn += amounts[k];
        }
        require(totalOut >= minOut, "insufficient output");
        // one record for the whole call, net amounts, the caller as owner
        agency.record(rec.nf, msg.sender, rec.proof, rec.rootRCL, rec.rootAT,
                      1, tokenIn, totalIn, tokenOut, totalOut, 0);
        emit SplitSwap(msg.sender, tokenIn, totalIn, tokenOut, totalOut, pools.length);
    }
}
