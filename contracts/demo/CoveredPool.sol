// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Interfaces.sol";

// A covered pool: a registered venue that integrates recording.
// Mock pricing: a fixed quote price, priceNum/priceDen units of token1 per
// unit of token0, set by the pool admin (stands in for an AMM curve).
//
// Entry-contract rule (SPEC section 3): the pool records the swap itself,
// reporting its caller as the owner, UNLESS a registered entry contract
// calls it (then that contract records once with the net amounts).
// There is no swap path that neither records nor is called by a registered
// entry contract, so a direct call records or reverts.
contract CoveredPool is ICoveredPool {
    IAgency public immutable agency;
    address public immutable token0;
    address public immutable token1;
    address public immutable admin;
    uint256 public priceNum;
    uint256 public priceDen;

    event Swapped(address indexed caller, address tokenIn, uint256 amountIn,
                  address tokenOut, uint256 amountOut, bool recordedHere);

    constructor(address _agency, address _token0, address _token1,
                uint256 _priceNum, uint256 _priceDen) {
        agency = IAgency(_agency);
        token0 = _token0; token1 = _token1;
        priceNum = _priceNum; priceDen = _priceDen;
        admin = msg.sender;
    }

    function setPrice(uint256 _priceNum, uint256 _priceDen) external {
        require(msg.sender == admin, "not the pool admin");
        require(_priceNum != 0 && _priceDen != 0, "zero price");
        priceNum = _priceNum; priceDen = _priceDen;
    }

    function quote(address tokenIn, uint256 amountIn)
        public view returns (address tokenOut, uint256 amountOut)
    {
        if (tokenIn == token0) {
            return (token1, amountIn * priceNum / priceDen);
        }
        require(tokenIn == token1, "token not in this pool");
        return (token0, amountIn * priceDen / priceNum);
    }

    function swap(address tokenIn, uint256 amountIn, uint256 minOut, address to,
        RecArgs calldata rec) external returns (uint256 amountOut)
    {
        address tokenOut;
        (tokenOut, amountOut) = quote(tokenIn, amountIn);
        require(amountOut != 0 && amountOut >= minOut, "insufficient output");

        bool recordHere = !agency.isEntry(msg.sender);
        if (recordHere) {
            // this pool is the entry contract of the call: record first,
            // then execute; any failure reverts both
            agency.record(rec.nf, msg.sender, rec.proof, rec.rootRCL, rec.rootAT,
                          1, tokenIn, amountIn, tokenOut, amountOut, 0);
        }
        require(IERC20Like(tokenIn).transferFrom(msg.sender, address(this), amountIn), "pull failed");
        require(IERC20Like(tokenOut).transfer(to, amountOut), "pay failed");
        emit Swapped(msg.sender, tokenIn, amountIn, tokenOut, amountOut, recordHere);
    }
}
