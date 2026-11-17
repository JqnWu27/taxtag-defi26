// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Shared interfaces of the TaxTag demo contracts.

// What a taxpayer hands an entry contract together with the transfer request:
// the nullifier NF_i, the Groth16 recording proof flattened as
// [a0, a1, b00, b01, b10, b11, c0, c1], and the two roots the proof cites.
struct RecArgs {
    uint256 nf;
    uint256[8] proof;
    uint256 rootRCL;
    uint256 rootAT;
}

// A PSL non-membership path for the position being closed (the agency
// contract stores roots only, so the caller supplies the path).
struct PslPath {
    uint256[] sibs;
    uint256 oldKey;
    uint256 oldValue;
    bool isOld0;
}

interface IAgency {
    function isEntry(address) external view returns (bool);
    function isVenue(address) external view returns (bool);
    function assetOf(address token) external view returns (uint16 id, address feed);
    function record(
        uint256 nf, address owner, uint256[8] calldata proof,
        uint256 rootRCL, uint256 rootAT,
        uint256 op, address tokenIn, uint256 amountIn,
        address tokenOut, uint256 amountOut, uint256 positionId
    ) external returns (uint256 leafIndex);
    function recordPassive(uint256 positionId, uint256 kind,
        address tokenA, uint256 amountA, address tokenB, uint256 amountB,
        uint256[] calldata sibs, uint256 oldKey, uint256 oldValue, bool isOld0) external;
}

interface IERC20Like {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IPriceFeedLike { function price() external view returns (uint256); }

interface IPool {
    function quote(address tokenIn, uint256 amountIn)
        external view returns (address tokenOut, uint256 amountOut);
}

interface ICoveredPool is IPool {
    function swap(address tokenIn, uint256 amountIn, uint256 minOut, address to,
        RecArgs calldata rec) external returns (uint256 amountOut);
}

interface IPlainPool is IPool {
    function swap(address tokenIn, uint256 amountIn, uint256 minOut, address to)
        external returns (uint256 amountOut);
}
