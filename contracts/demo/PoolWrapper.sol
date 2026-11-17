// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Interfaces.sol";

// A wrapper that adds recording to a service that cannot be upgraded: a
// registered entry contract in front of an UNREGISTERED PlainPool. A swap
// through the wrapper is recorded. A direct call to the PlainPool bypasses
// it and executes unrecorded (the limit the paper's Scope states).
contract PoolWrapper {
    IAgency public immutable agency;
    IPlainPool public immutable pool;

    event WrappedSwap(address indexed owner, address tokenIn, uint256 amountIn,
                      address tokenOut, uint256 amountOut);

    constructor(address _agency, address _pool) {
        agency = IAgency(_agency);
        pool = IPlainPool(_pool);
    }

    function swap(address tokenIn, uint256 amountIn, uint256 minOut,
        RecArgs calldata rec) external returns (uint256 amountOut)
    {
        (address tokenOut, ) = pool.quote(tokenIn, amountIn);
        require(IERC20Like(tokenIn).transferFrom(msg.sender, address(this), amountIn), "pull failed");
        require(IERC20Like(tokenIn).approve(address(pool), amountIn), "approve failed");
        amountOut = pool.swap(tokenIn, amountIn, minOut, msg.sender);
        agency.record(rec.nf, msg.sender, rec.proof, rec.rootRCL, rec.rootAT,
                      1, tokenIn, amountIn, tokenOut, amountOut, 0);
        emit WrappedSwap(msg.sender, tokenIn, amountIn, tokenOut, amountOut);
    }
}
