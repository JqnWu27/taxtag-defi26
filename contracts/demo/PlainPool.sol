// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Interfaces.sol";

// An unchanged, UNREGISTERED service: a pool that knows nothing about the
// agency contract. It can be put behind PoolWrapper, which records; a
// direct call here succeeds unrecorded (the documented limit).
contract PlainPool is IPlainPool {
    address public immutable token0;
    address public immutable token1;
    address public immutable admin;
    uint256 public priceNum;
    uint256 public priceDen;

    event Swapped(address indexed caller, address tokenIn, uint256 amountIn,
                  address tokenOut, uint256 amountOut);

    constructor(address _token0, address _token1, uint256 _priceNum, uint256 _priceDen) {
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

    function swap(address tokenIn, uint256 amountIn, uint256 minOut, address to)
        external returns (uint256 amountOut)
    {
        address tokenOut;
        (tokenOut, amountOut) = quote(tokenIn, amountIn);
        require(amountOut != 0 && amountOut >= minOut, "insufficient output");
        require(IERC20Like(tokenIn).transferFrom(msg.sender, address(this), amountIn), "pull failed");
        require(IERC20Like(tokenOut).transfer(to, amountOut), "pay failed");
        emit Swapped(msg.sender, tokenIn, amountIn, tokenOut, amountOut);
    }
}
