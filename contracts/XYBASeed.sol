// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// @author: XYBA PARTY DEV
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

interface ERC721XYBAAdherent {
    function mint(bytes memory signature, uint256 tokenId, address to) external payable;
    function ownerOf(uint256 tokenId) external view returns (address owner);
}

contract XYBASeed is
ERC721Enumerable,
ERC721Holder,
Ownable,
Pausable,
ReentrancyGuard {
    using SafeMath for uint256;
    using Math for uint256;
    using Strings for uint256;
    using Counters for Counters.Counter;

    /*
	* Public Variables
	*/
    /// max address mint supply, 0 means no limit
    uint256 public maxAddressMintSupply = 1000;
    /// max free mint supply, 0 means no limit
    uint256 public maxFreeMintSupply = 1000;
    /// max count of one wallet can mint, 0 means no limit
    uint256 public maxMintCountLimitOfOneAddress = 10;
    /// base token uri
    string public baseTokenURI;
    /// XYBA Adherent Contract
    ERC721XYBAAdherent public adherentContract;

    /*
    * Private Variables
    */
    /// token index counter
    Counters.Counter private _tokenIndex;
    /// address mint counter
    Counters.Counter private _addressMintedCounter;
    /// free mint counter
    Counters.Counter private _freeMintedCounter;
    /// record the used whitelist signature
    mapping(bytes => bool) private _signatureUsed;
    /// record each address mint count
    mapping(address => uint256) private _mintCounter;
    /// address used to verify sign
    address private _signerAddress;

    /*
    * Constructor
    */
    /// Initial Smart Contract
    /// @param name contract name
    /// @param symbol contract symbol
    /// @param baseTokenURI_ base URI of all tokens
    /// @param signerAddress the admin address to verify signature
    constructor(
        string memory name,
        string memory symbol,
        string memory baseTokenURI_,
        address signerAddress
    )
    ERC721(name, symbol)
    {
        baseTokenURI = baseTokenURI_;
        _signerAddress = signerAddress;
    }


    // ======================================================== Owner Functions
    /// Set the base URI of tokens
    /// @param baseTokenURI_ new base URI
    function setBaseURI(string memory baseTokenURI_) external onlyOwner {
        baseTokenURI = baseTokenURI_;
    }

    /// Set the pause status
    /// @param isPaused pause or not
    function setPaused(bool isPaused) external onlyOwner {
        isPaused ? _pause() : _unpause();
    }

    /// Set Max Address Mint Supply
    /// @param count max address mint supply
    function setMaxAddressMintSupply(uint256 count) external onlyOwner {
        require(count >= totalSupply(), 'Max address mint supply needs to be greater than total supply');
        maxAddressMintSupply = count;
    }

    /// Set Max Free Mint Supply
    /// @param count max free mint supply
    function setMaxFreeMintSupply(uint256 count) external onlyOwner {
        maxFreeMintSupply = count;
    }

    /// Set Max Mint Count Of One Address
    /// @param count max mint count limit of one address
    function setMaxMintCountLimitOfOneAddress(uint256 count) external onlyOwner {
        maxMintCountLimitOfOneAddress = count;
    }

    /// Set XYBA Adherent Contract
    /// @param _adherentContract XYBA Adherent contract address
    function setXYBAAdherentContract(ERC721XYBAAdherent _adherentContract) external onlyOwner {
        adherentContract = _adherentContract;
    }

    /// Airdrop NFTs to Receiver
    /// @param receiver the receiver address
    /// @param count tokens count
    function airdrop(address receiver, uint count) external whenNotPaused onlyOwner {
        for (uint i = 0; i < count; i++) {
            _airdrop(receiver);
        }
    }

    /// Owner Mint NFTs to Receiver
    function ownerMint() external whenNotPaused onlyOwner {
        _safeMint(address(this));
    }

    /// Owner Batch Mint NFTs to Receiver
    function ownerMintBatch(uint256 count) external whenNotPaused onlyOwner {
        for (uint i = 0; i < count; i++) {
            _safeMint(address(this));
        }
    }

    /// @notice Transfer Token from contract to user wallet
    /// @param to target user wallet address
    /// @param tokenId token to transfer
    function ownerTransfer(address to, uint256 tokenId) external onlyOwner {
        require(ownerOf(tokenId) == address(this), 'Contract self is not token owner');
        _safeTransfer(address(this), to, tokenId, new bytes(0));
    }

    /// @notice Withdraw
    /// @param amount the withdraw amount
    function withdraw(uint256 amount) external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance >= amount, "Not enough balance left to withdraw.");
        payable(msg.sender).transfer(amount);
    }


    // ======================================================== External Functions
    /// Free Mint
    /// @dev free mint token using verified signature signed by an admin address
    /// @param signature signed by an admin address
    function freeMint(bytes memory signature) external whenNotPaused nonReentrant {
        require(_canMint(), "Mint count over limit.");
        require(_isValidFreeMintSignature(signature), "Address is not in whitelist.");
        require(!_signatureUsed[signature], "Signature has already been used.");
        require(_hasEnoughAddressMintSupply(), "Not enough address mint NFTs left!");
        require(_hasEnoughFreeMintSupply(), "Not enough free mint NFTs left!");
        _signatureUsed[signature] = true;
        _freeMint();
    }

    /// Mint Token
    /// @dev mints token
    function mint(bytes memory signature, uint256 price) external payable whenNotPaused nonReentrant {
        require(_canMint(), "Mint count over limit.");
        require(_isValidMintSignature(signature, price), "Signature is error.");
        require(_hasEnoughAddressMintSupply(), "Not enough address mint NFTs left!");
        require(msg.value >= price, "Not enough balance left!");
        _mint();
    }

    /// Mint XYBAAdherent
    /// @param signature signed by an admin address
    /// @param mintSignature mint sign
    /// @param tokenId tokenId
    /// @param to address to mint to
    function mintAdherent(bytes memory signature, bytes memory mintSignature, uint256 tokenId, address to) external payable whenNotPaused nonReentrant {
        require(address(adherentContract) != address(0), "XYBA Adherent contract address is empty.");
        require(_exists(tokenId), "Token is not exist.");
        require(msg.sender == ownerOf(tokenId) || ownerOf(tokenId) == address(this), "You don't own this token.");
        require(_isValidMintAdherentSignature(signature, mintSignature, tokenId, to), "Signature is error.");

        _burn(tokenId);
        adherentContract.mint(mintSignature, tokenId, to);
    }

    /// @dev has enough free mint supply
    function canFreeMint() public view virtual returns (bool) {
        return _hasEnoughFreeMintSupply();
    }

    /// @dev current free minted supply
    function totalFreeMintSupply() public view virtual returns (uint256) {
        return _freeMintedCounter.current();
    }

    /// @dev See {IERC721Metadata-tokenURI}.
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        _requireMinted(tokenId);
        return string(abi.encodePacked(baseTokenURI, tokenId.toString()));
    }

    /// Get Token Ids
    /// @dev Get the token ids owned by owner
    /// @param _owner owner address of tokens
    /// @return token Ids array
    function tokensOfOwner(address _owner) external view returns (uint[] memory) {
        return _tokensOfOwner(_owner);
    }


    // ======================================================== Internal Functions
    /// Verify Signature For Free Mint
    /// @param signature signed by an admin address
    /// @return if the signature is valid
    function _isValidFreeMintSignature(bytes memory signature) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(name(), msg.sender));
        return _isValidHash(hash, signature);
    }

    /// Verify Signature For Mint
    /// @param signature signed by an admin address
    /// @param price mint price
    /// @return if the signature is valid
    function _isValidMintSignature(bytes memory signature, uint256 price) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(name(), msg.sender, price));
        return _isValidHash(hash, signature);
    }

    /// Verify Signature For Mint Adherent
    /// @param signature signed by an admin address
    /// @param mintSignature mint sign
    /// @param tokenId tokenId
    /// @param to address to mint to
    /// @return if the signature is valid
    function _isValidMintAdherentSignature(bytes memory signature, bytes memory mintSignature, uint256 tokenId, address to) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(name(), msg.sender, mintSignature, tokenId, to));
        return _isValidHash(hash, signature);
    }

    /// Verify Hash And Signature
    /// @param signature signed by an admin address
    /// @return if the signature is valid
    function _isValidHash(bytes32 hash, bytes memory signature) internal view returns (bool) {
        bytes32 message = ECDSA.toEthSignedMessageHash(hash);
        address recoveredAddress = ECDSA.recover(message, signature);
        return recoveredAddress != address(0) && recoveredAddress == _signerAddress;
    }

    /// Verify Max Mint Supply
    /// @dev check the supply of free mint is enough or not
    /// @return is enough
    function _hasEnoughAddressMintSupply() internal view returns (bool) {
        // no limit
        if (maxAddressMintSupply == 0) {
            return true;
        }
        return _addressMintedCounter.current() + 1 <= maxAddressMintSupply;
    }

    /// Verify Free Mint Supply
    /// @dev check the supply of free mint is enough or not
    /// @return is enough
    function _hasEnoughFreeMintSupply() internal view returns (bool) {
        // no limit
        if (maxFreeMintSupply == 0) {
            return true;
        }
        return _freeMintedCounter.current() + 1 <= maxFreeMintSupply;
    }

    /// Can Mint
    /// @dev check sender mint limit is enough or not
    /// @return is enough
    function _canMint() internal view returns (bool) {
        // no limit
        if (maxMintCountLimitOfOneAddress == 0) {
            return true;
        }
        return _mintCounter[msg.sender] + 1 <= maxMintCountLimitOfOneAddress;
    }

    /// Get Token Ids
    /// @dev Get the token ids owned by owner
    /// @param _owner owner address of tokens
    /// @return token Ids array
    function _tokensOfOwner(address _owner) private view returns (uint[] memory) {
        uint tokenCount = balanceOf(_owner);
        uint[] memory tokensId = new uint256[](tokenCount);

        for (uint i = 0; i < tokenCount; i++) {
            tokensId[i] = tokenOfOwnerByIndex(_owner, i);
        }
        return tokensId;
    }

    /// Free Mint
    /// @dev free mint NFT to the sender address
    function _freeMint() private {
        _safeMint(msg.sender);
        _freeMintedCounter.increment();
        _addressMintedCounter.increment();
        unchecked {
            _mintCounter[msg.sender] += 1;
        }
    }

    /// Mint
    /// @dev mint NFT to the sender address
    function _mint() private {
        _safeMint(msg.sender);
        _addressMintedCounter.increment();
        unchecked {
            _mintCounter[msg.sender] += 1;
        }
    }

    /// Airdrop
    /// @dev airdrop NFT to the sender address
    function _airdrop(address receiver) private {
        _safeMint(receiver);
    }

    /// Safe Mint
    /// @dev mint NFT to the receiver address
    function _safeMint(address receiver) private {
        uint newTokenID = _tokenIndex.current();
        _safeMint(receiver, newTokenID);
        _tokenIndex.increment();
    }
} // End of Contract
