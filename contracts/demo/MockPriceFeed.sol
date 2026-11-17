// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Mock price feed: the oracle value, in the oracle's unit (USD in the demo),
// of ONE token unit of the asset. Set by its deployer.
contract MockPriceFeed {
    address public immutable admin;
    uint256 public price;

    event PriceSet(uint256 price);

    constructor(uint256 _price) { admin = msg.sender; price = _price; }

    function setPrice(uint256 _price) external {
        require(msg.sender == admin, "not the feed admin");
        price = _price;
        emit PriceSet(_price);
    }
}
