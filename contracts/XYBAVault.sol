// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// @author: XYBA PARTY DEV
import './libs/IBEP20.sol';
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/*
The XYBA Vault is used to securely store and process tokens that users deposit or withdraw between their accounts and wallets.
*/
contract XYBAVault is Ownable, Pausable, ReentrancyGuard {
    // ======================================================== Events
    event Deposited(address indexed from, uint256 amount);
    event Withdrawn(address indexed to, uint256 amount);
    event TokenWithdrawn(IBEP20 indexed token, address indexed to, uint256 amount);

    // ======================================================== Constructor
    constructor(){}

    // ======================================================== Owner Functions
    /// Set the pause status
    /// @param isPaused pause or not
    function setPaused(bool isPaused) external onlyOwner {
        isPaused ? _pause() : _unpause();
    }
    /// @notice Withdraw
    /// @param amount the withdraw amount
    /// @param to target address
    function withdraw(uint256 amount, address to) external onlyOwner {
        uint256 balance = getBalance();
        require(balance >= amount, "Not enough balance left to withdraw.");

        payable(to).transfer(amount);

        emit Withdrawn(to, amount);
    }
    /// @notice Withdraw Token
    /// @param token BEP20 token address
    /// @param to target address
    /// @param amount number of tokens
    function withdrawToken(IBEP20 token, address to, uint256 amount) external onlyOwner {
        require(address(token) != address(0), "Invalid token address");
        require(to != address(0), "Invalid withdraw target address");
        require(amount > 0, "Amount must be greater than 0");
        require(getTokenBalance(token) >= amount, "Not enough balance left to withdraw.");

        token.transfer(to, amount);

        emit TokenWithdrawn(token, to, amount);
    }

    // ======================================================== External Functions
    /// Deposit
    function deposit() public payable whenNotPaused nonReentrant {
        _deposit();
    }

    /// Check Total Balance
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
    /// Check Balance Of BEP20 Token
    /// @param token BEP20 token
    function getTokenBalance(IBEP20 token) public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    /// Receive
    receive() external payable {
        _deposit();
    }
    /// Fallback
    fallback() external payable {
        _deposit();
    }

    // ======================================================== External Functions
    function _deposit() private {
        if (msg.value > 0) {
            emit Deposited(msg.sender, msg.value);
        }
    }
} // End of Contract
