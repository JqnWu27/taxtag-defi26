// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Interfaces.sol";

// A covered lending venue (registered with the agency contract as a venue).
//
// Recorded with a taxpayer proof (it is the entry contract of these calls):
//   pledge  (op 2)  collateral in, optional loan out in the SAME call -> ONE
//                   pledge record carrying the loan and the new position id
//   borrow  (op 3)  loan out, position id
//   repay   (op 4)  coins repaid in, position id
//   claimReward (op 5)  reward out
// Written to the PSL with NO taxpayer proof (SPEC section 5):
//   liquidate  (kind 1)  collateral seized, debt covered
//   withdraw   (kind 2)  collateral returned, interest earned
// Writes nothing: withdrawPartial (its interest is counted at the close).
//
// Mock economics: prices come from the agency contract's asset table feeds;
// interest on the collateral is credited by the venue admin (stands in for
// an interest model) and paid in the collateral token at the full
// withdrawal; a liquidation repays the whole debt and seizes the whole
// collateral.
contract LendingVenue {
    uint256 public constant LTV_BPS = 7500;            // borrow up to 75% of the collateral value
    uint256 public constant LIQ_THRESHOLD_BPS = 8000;  // liquidatable above 80%

    IAgency public immutable agency;
    address public immutable admin;
    address public immutable rewardToken;
    uint256 public nextPositionId;                     // venue-assigned, from idBase

    struct Position {
        address owner;
        address collToken;
        uint256 collAmount;
        address debtToken;
        uint256 debt;
        uint256 interest;      // earned so far, in collateral-token units
        bool open;
    }
    mapping(uint256 => Position) public positions;
    mapping(address => uint256) public claimable;      // mock rewards, in rewardToken

    event Pledged(uint256 indexed positionId, address indexed owner,
                  address collToken, uint256 collAmount, address loanToken, uint256 loanAmount);
    event Borrowed(uint256 indexed positionId, address loanToken, uint256 amount);
    event Repaid(uint256 indexed positionId, address debtToken, uint256 amount);
    event PartiallyWithdrawn(uint256 indexed positionId, uint256 amount);
    event Withdrawn(uint256 indexed positionId, uint256 collateralReturned, uint256 interest);
    event Liquidated(uint256 indexed positionId, address indexed liquidator,
                     uint256 collateralSeized, uint256 debtCovered);
    event RewardClaimed(address indexed owner, uint256 amount);

    constructor(address _agency, uint256 idBase, address _rewardToken) {
        agency = IAgency(_agency);
        admin = msg.sender;
        nextPositionId = idBase;
        rewardToken = _rewardToken;
    }

    modifier onlyAdmin() { require(msg.sender == admin, "not the venue admin"); _; }

    // ---- prices and health ---------------------------------------------------
    function _price(address token) internal view returns (uint256) {
        (uint16 id, address feed) = agency.assetOf(token);
        require(id != 0, "asset not covered");
        return IPriceFeedLike(feed).price();
    }

    function _within(Position storage p, uint256 bps) internal view returns (bool) {
        if (p.debt == 0) return true;
        return p.collAmount * _price(p.collToken) * bps >= p.debt * _price(p.debtToken) * 10000;
    }

    // ---- recorded operations ---------------------------------------------------
    function pledge(address collToken, uint256 collAmount,
        address loanToken, uint256 loanAmount, RecArgs calldata rec)
        external returns (uint256 id)
    {
        require(collAmount != 0, "no collateral");
        id = nextPositionId++;
        Position storage p = positions[id];
        p.owner = msg.sender;
        p.collToken = collToken; p.collAmount = collAmount;
        p.open = true;
        if (loanAmount != 0) {
            p.debtToken = loanToken; p.debt = loanAmount;
            require(_within(p, LTV_BPS), "loan exceeds the collateral limit");
        }
        // ONE pledge record; the loan of the same call rides in asset/amount out
        agency.record(rec.nf, msg.sender, rec.proof, rec.rootRCL, rec.rootAT,
                      2, collToken, collAmount,
                      loanAmount != 0 ? loanToken : address(0), loanAmount, id);
        require(IERC20Like(collToken).transferFrom(msg.sender, address(this), collAmount), "pull failed");
        if (loanAmount != 0) {
            require(IERC20Like(loanToken).transfer(msg.sender, loanAmount), "loan failed");
        }
        emit Pledged(id, msg.sender, collToken, collAmount, loanToken, loanAmount);
    }

    function borrow(uint256 id, address loanToken, uint256 amount, RecArgs calldata rec) external {
        Position storage p = positions[id];
        require(p.open && p.owner == msg.sender, "not your open position");
        require(amount != 0, "nothing to borrow");
        if (p.debt == 0) p.debtToken = loanToken;
        require(p.debtToken == loanToken, "one debt token per position");
        p.debt += amount;
        require(_within(p, LTV_BPS), "loan exceeds the collateral limit");
        agency.record(rec.nf, msg.sender, rec.proof, rec.rootRCL, rec.rootAT,
                      3, address(0), 0, loanToken, amount, id);
        require(IERC20Like(loanToken).transfer(msg.sender, amount), "loan failed");
        emit Borrowed(id, loanToken, amount);
    }

    function repay(uint256 id, uint256 amount, RecArgs calldata rec) external {
        Position storage p = positions[id];
        require(p.open && p.owner == msg.sender, "not your open position");
        require(amount != 0 && amount <= p.debt, "bad repay amount");
        p.debt -= amount;
        agency.record(rec.nf, msg.sender, rec.proof, rec.rootRCL, rec.rootAT,
                      4, p.debtToken, amount, address(0), 0, id);
        require(IERC20Like(p.debtToken).transferFrom(msg.sender, address(this), amount), "pull failed");
        emit Repaid(id, p.debtToken, amount);
    }

    function setClaimable(address user, uint256 amount) external onlyAdmin {
        claimable[user] = amount;
    }

    function claimReward(uint256 amount, RecArgs calldata rec) external {
        require(amount != 0 && claimable[msg.sender] >= amount, "nothing to claim");
        claimable[msg.sender] -= amount;
        agency.record(rec.nf, msg.sender, rec.proof, rec.rootRCL, rec.rootAT,
                      5, address(0), 0, rewardToken, amount, 0);
        require(IERC20Like(rewardToken).transfer(msg.sender, amount), "pay failed");
        emit RewardClaimed(msg.sender, amount);
    }

    // ---- unrecorded: partial withdrawal ----------------------------------------
    // Writes nothing (SPEC section 5). The position stays open.
    function withdrawPartial(uint256 id, uint256 amount) external {
        Position storage p = positions[id];
        require(p.open && p.owner == msg.sender, "not your open position");
        require(amount != 0 && amount < p.collAmount, "use withdraw to close");
        p.collAmount -= amount;
        require(_within(p, LTV_BPS), "would leave the loan under-collateralized");
        require(IERC20Like(p.collToken).transfer(msg.sender, amount), "pay failed");
        emit PartiallyWithdrawn(id, amount);
    }

    // ---- passive events: no taxpayer proof ---------------------------------------
    function creditInterest(uint256 id, uint256 amount) external onlyAdmin {
        require(positions[id].open, "position not open");
        positions[id].interest += amount;
    }

    // Full withdrawal: closes the position. Needs no recording proof, so it
    // stays open to a revoked tag.
    function withdraw(uint256 id, PslPath calldata path) external {
        Position storage p = positions[id];
        require(p.open && p.owner == msg.sender, "not your open position");
        require(p.debt == 0, "repay the loan first");
        p.open = false;
        uint256 coll = p.collAmount;
        uint256 interest = p.interest;
        agency.recordPassive(id, 2, p.collToken, coll,
                             interest != 0 ? p.collToken : address(0), interest,
                             path.sibs, path.oldKey, path.oldValue, path.isOld0);
        require(IERC20Like(p.collToken).transfer(msg.sender, coll + interest), "pay failed");
        emit Withdrawn(id, coll, interest);
    }

    function isLiquidatable(uint256 id) public view returns (bool) {
        Position storage p = positions[id];
        return p.open && p.debt != 0 && !_within(p, LIQ_THRESHOLD_BPS);
    }

    // Liquidation: executes without the taxpayer. The liquidator covers the
    // whole debt and seizes the whole collateral.
    function liquidate(uint256 id, PslPath calldata path) external {
        require(isLiquidatable(id), "position is healthy");
        Position storage p = positions[id];
        p.open = false;
        uint256 coll = p.collAmount;
        uint256 debt = p.debt;
        p.debt = 0;
        agency.recordPassive(id, 1, p.collToken, coll, p.debtToken, debt,
                             path.sibs, path.oldKey, path.oldValue, path.isOld0);
        require(IERC20Like(p.debtToken).transferFrom(msg.sender, address(this), debt), "pull failed");
        require(IERC20Like(p.collToken).transfer(msg.sender, coll), "pay failed");
        emit Liquidated(id, msg.sender, coll, debt);
    }
}
