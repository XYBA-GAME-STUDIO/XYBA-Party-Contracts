// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

// @author: XYBA PARTY DEV
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

contract XYBAAccessory is
ERC1155,
ERC1155Holder,
Ownable,
Pausable,
ERC1155Supply,
ReentrancyGuard
{
    using SafeMath for uint256;
    using Math for uint256;
    using Strings for uint256;
    using Counters for Counters.Counter;

    /*
     * Public Variables
    */
    /// base token uri
    string public baseUri;
    /// source contract address
    address public sourceContractAddress;
    /// accessory type
    mapping(uint256 => uint256) public accessoryTypes;
    /// token id => max mint supply
    mapping(uint256 => uint256) public maxAddressMintSupply;


    /*
     * Private Variables
    */
    /// address used to verify sign
    address private _signerAddress;
    /// token id => minted supply
    mapping(uint256 => uint256) private _tokenMintedSupply;

    /*
    * Constructor
    */
    /// Initial Smart Contract
    /// @param _uri base URI of all tokens
    /// @param signerAddress the admin address to verify signature
    constructor(
        string memory _uri,
        address signerAddress
    )
    ERC1155(_uri) {
        baseUri = _uri;
        _signerAddress = signerAddress;
    }

    // ======================================================== Owner Functions
    /// Set the base URI of tokens
    /// @param _uri new base URI
    function setURI(string memory _uri) public onlyOwner {
        _setURI(_uri);
        baseUri = _uri;
    }

    /// Set the pause status
    /// @param isPaused pause or not
    function setPaused(bool isPaused) public onlyOwner {
        isPaused ? _pause() : _unpause();
    }

    /// Set the source contract address to transfer to self
    /// @param _sourceContractAddress source contract address
    function setSourceContractAddress(address _sourceContractAddress) public onlyOwner {
        sourceContractAddress = _sourceContractAddress;
    }

    /// Set max mint supply of each token
    /// @param ids token ids
    /// @param maxSupplies max mint supply of each token
    function setMaxAddressMintSupply(uint256[] memory ids, uint256[] memory maxSupplies) public onlyOwner {
        require(ids.length == maxSupplies.length, "Ids and maxSupplies length mismatch.");
        for (uint256 i; i < ids.length; i++) {
            maxAddressMintSupply[ids[i]] = maxSupplies[i];
        }
    }

    /// Mint token to address for owner
    /// @param to receiver address
    /// @param id token id
    /// @param amount token amount
    /// @param _type token type
    function ownerMint(address to, uint256 id, uint256 amount, uint256 _type) public onlyOwner whenNotPaused {
        _mint(to, id, amount, new bytes(0));
        if (accessoryTypes[id] != _type) {
            accessoryTypes[id] = _type;
        }
    }
    /// Batch Mint token to address for owner
    /// @param to receiver address
    /// @param ids token ids
    /// @param amounts amounts of each token
    /// @param types types of each token
    function ownerMintBatch(address to, uint256[] memory ids, uint256[] memory amounts, uint256[] memory types) public onlyOwner whenNotPaused {
        require(ids.length == types.length, "Ids and types length mismatch.");
        _mintBatch(to, ids, amounts, new bytes(0));
        for (uint256 i; i < types.length; i++) {
            if (accessoryTypes[ids[i]] != types[i]) {
                accessoryTypes[ids[i]] = types[i];
            }
        }
    }

    /// @notice Owner transfer tokens to user wallet address
    /// @param to target wallet address
    /// @param ids token ids
    /// @param amounts token amounts
    function ownerBatchTransfer(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts
    ) public onlyOwner whenNotPaused {
        _safeBatchTransferFrom(address(this), to, ids, amounts, new bytes(0));
    }

    /// @notice Withdraw
    /// @param amount the withdraw amount
    function withdraw(uint256 amount) external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance >= amount, "Not enough balance left to withdraw.");
        payable(msg.sender).transfer(amount);
    }

    // ======================================================== External Functions
    /// @notice Contract transfer tokens to user wallet address
    /// @param from from wallet address
    /// @param to target wallet address
    /// @param ids token ids
    /// @param amounts token amounts
    function contractBatchTransfer(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts
    ) external whenNotPaused {
        require(msg.sender == sourceContractAddress, 'Message sender is not source contract.');
        _safeBatchTransferFrom(from, to, ids, amounts, new bytes(0));
    }
    /// @notice Contract batch burn tokens
    /// @param from from wallet address
    /// @param ids token ids
    /// @param amounts token amounts
    function contractBatchBurn(
        address from,
        uint256[] memory ids,
        uint256[] memory amounts
    ) external whenNotPaused {
        require(msg.sender == sourceContractAddress, 'Message sender is not source contract.');
        _burnBatch(from, ids, amounts);
    }

    /// Mint Token
    /// @param signature signed by an admin address
    /// @param id token id
    /// @param amount token amount
    /// @param _type token type
    /// @param price mint price
    /// @dev mints token
    function mint(bytes memory signature, uint256 id, uint256 amount, uint256 _type, uint256 price) external payable whenNotPaused nonReentrant {
        require(_canMint(id, amount), "Mint amount over limit.");
        require(_isValidMintSignature(signature, id, amount, _type, price), "Signature is error.");
        require(msg.value >= price, "Not enough balance left!");
        _mint(msg.sender, id, amount, new bytes(0));
        if (accessoryTypes[id] != _type) {
            accessoryTypes[id] = _type;
        }
        unchecked {
            _tokenMintedSupply[id] += amount;
        }
    }

    /// Batch Mint Token
    /// @param signature signed by an admin address
    /// @param ids token ids
    /// @param amounts amounts of each token
    /// @param types types of each token
    /// @param price mint price
    /// @dev mints token
    function mintBatch(bytes memory signature, uint256[] memory ids, uint256[] memory amounts, uint256[] memory types, uint256 price) external payable whenNotPaused nonReentrant {
        require(_isValidMintBatchSignature(signature, ids, amounts, types, price), "Signature is error.");
        require(ids.length == types.length, "Ids and types length mismatch.");
        require(ids.length == amounts.length, "Ids and amounts length mismatch.");
        require(msg.value >= price, "Not enough balance left!");
        for (uint256 i; i < ids.length; i++) {
            require(_canMint(ids[i], amounts[i]), "Mint amount over limit.");
        }
        _mintBatch(msg.sender, ids, amounts, new bytes(0));
        unchecked {
            for (uint256 i; i < types.length; i++) {
                _tokenMintedSupply[ids[i]] += amounts[i];
                if (accessoryTypes[ids[i]] != types[i]) {
                    accessoryTypes[ids[i]] = types[i];
                }
            }
        }
    }

    /// Get accessory type with tokenId
    function accessoryType(uint256 _tokenId) external view returns (uint256) {
        return accessoryTypes[_tokenId];
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC1155, ERC1155Receiver) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function uri(uint256 tokenId) public view virtual override returns (string memory) {
        require(exists(tokenId), 'Token id is not exists.');
        return string(abi.encodePacked(baseUri, tokenId.toString()));
    }

    // ======================================================== Internal Functions
    function _beforeTokenTransfer(address operator, address from, address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data)
    internal
    whenNotPaused
    override(ERC1155, ERC1155Supply)
    {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
    }

    /// Verify Signature For Mint
    /// @param signature signed by an admin address
    /// @param id token id
    /// @param amount token amount
    /// @param _type token type
    /// @param price mint price
    /// @return if the signature is valid
    function _isValidMintSignature(bytes memory signature, uint256 id, uint256 amount, uint256 _type, uint256 price) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked("XYBA Accessory Token", msg.sender, id, amount, _type, price));
        return _isValidHash(hash, signature);
    }
    /// Verify Signature For Mint Batch
    /// @param signature signed by an admin address
    /// @param ids token ids
    /// @param amounts amounts of each token
    /// @param types types of each token
    /// @param price mint price
    /// @return if the signature is valid
    function _isValidMintBatchSignature(bytes memory signature, uint256[] memory ids, uint256[] memory amounts, uint256[] memory types, uint256 price) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked("XYBA Accessory Token", msg.sender, ids, amounts, types, price));
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
    /// Verify can mint amount of token
    /// @param id token id
    /// @param amount mint amount
    function _canMint(uint256 id, uint256 amount) private view returns (bool) {
        // no limit
        if (maxAddressMintSupply[id] == 0) {
            return true;
        }
        return _tokenMintedSupply[id] + amount <= maxAddressMintSupply[id];
    }
}
