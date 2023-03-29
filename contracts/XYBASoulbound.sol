// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// @author: XYBA PARTY DEV
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract XYBASoulbound is ERC721, Ownable {
    using Counters for Counters.Counter;

    /*
	* Variables
	*/
    /// base token uri
    string public baseTokenURI;
    Counters.Counter private _tokenIdCounter;

    /*
    * Constructor
    */
    /// Initial Smart Contract
    /// @param name contract name
    /// @param symbol contract symbol
    /// @param baseTokenURI_ base URI of all tokens
    constructor(
        string memory name,
        string memory symbol,
        string memory baseTokenURI_
    )
    ERC721(name, symbol)
    {
        baseTokenURI = baseTokenURI_;
    }

    // ======================================================== Owner Functions
    /// Set the base URI of tokens
    /// @param baseTokenURI_ new base URI
    function setBaseURI(string memory baseTokenURI_) external onlyOwner {
        baseTokenURI = baseTokenURI_;
    }

    /// Mint to address
    /// @param to target address
    function safeMint(address to) external onlyOwner {
        require(balanceOf(to) == 0, "Each address can only have one Soul Bound token.");
        uint256 tokenId = _tokenIdCounter.current();
        _tokenIdCounter.increment();
        _safeMint(to, tokenId);
    }

    // ======================================================== Internal Functions
    /// Override transfer function, only allow owner mint
    function _beforeTokenTransfer(address from, address, uint256, uint256) pure internal override {
        require(from == address(0), "This a Soul Bound token. It cannot be transferred.");
    }
} // End of Contract
