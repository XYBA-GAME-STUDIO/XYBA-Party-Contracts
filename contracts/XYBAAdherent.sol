// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

// @author: XYBA PARTY DEV
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

interface IXYBAAccessory is IERC1155 {
    function accessoryType(uint256 _tokenId) external returns (uint256);
    function contractBatchTransfer(address from, address to, uint256[] memory ids, uint256[] memory amounts) external;
    function contractBatchBurn(address from, uint256[] memory ids, uint256[] memory amounts) external;
}

contract XYBAAdherent is
ERC721Enumerable,
ERC721Holder,
ERC1155Holder,
Ownable,
Pausable,
ReentrancyGuard
{
    using SafeMath for uint256;
    using SafeCast for uint256;
    using Math for uint256;
    using Strings for uint256;
    using Counters for Counters.Counter;

    struct Accessory {
        uint256 encodedAccessories;
        bool[8] isEquipped;
        uint256 operationCount;
    }

    event AccessoryWeared(
        address indexed requestFrom,
        uint256 indexed tokenId,
        bool[8] isEquipedBefore,
        uint256[8] accessoriesIdsBefore,
        bool[8] isEquiped,
        uint256[8] accessoriesIds,
        uint256 operationCount
    );
    event AccessoryTakenOff(
        address indexed requestFrom,
        uint256 indexed tokenId,
        uint256[8] accessoriesIds,
        uint256[] UnequippedTokenIds,
        uint256 operationCount
    );
    event AdherentRegenerated(
        address indexed requestFrom,
        address indexed to,
        uint256 indexed newTokenId,
        uint256[] burnedTokenIds
    );

    /*
	* Public Variables
	*/
    /// base token uri
    string public baseTokenURI;
    /// accessory contract
    IXYBAAccessory public accessoryAddress;
    /// token accessory data
    mapping(uint256 => Accessory) public tokenAccessoryData;
    /// operation count of wear and take off
    mapping(uint256 => uint256) public tokenAccessoryOperationCount;

    /*
    * Private Variables
    */
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

    /// Set accessory address
    /// @param _accessoryAddress accessory address
    /// @dev Only owner can do this
    /// @dev This should be an ERC1155 NFT address
    /// @dev If accessory address is set as zero address, accessory cannot be equipped.
    function setAccessoryAddress(IXYBAAccessory _accessoryAddress) external onlyOwner {
        accessoryAddress = _accessoryAddress;
    }

    /// @notice Withdraw
    /// @param amount the withdraw amount
    function withdraw(uint256 amount) external onlyOwner {
        uint256 balance = address(this).balance;
        require(balance >= amount, "Not enough balance left to withdraw.");
        payable(msg.sender).transfer(amount);
    }

    /// @notice Transfer Token from contract to user wallet
    /// @param to target user wallet address
    /// @param tokenId token to transfer
    function ownerTransfer(address to, uint256 tokenId) external onlyOwner {
        require(ownerOf(tokenId) == address(this), 'Contract self is not token owner');
        _safeTransfer(address(this), to, tokenId, new bytes(0));
    }


    // ======================================================== External Functions
    /// Mint Token To Address
    /// @dev mints token
    function mint(bytes memory signature, uint256 tokenId, address to) external payable whenNotPaused nonReentrant {
        require(_isValidMintSignature(signature, tokenId, to), "Signature is error.");
        _safeMint(to, tokenId);
    }

    /// Regenerate Token
    /// @dev Burn Tokens To Get A New One
    function regenerate(bytes memory signature, uint256[] calldata tokenIds, uint256 newTokenId, address to) external payable whenNotPaused nonReentrant {
        require(_isValidRegenerateSignature(signature, tokenIds, newTokenId, to), "Signature is error.");
        for (uint256 i; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];
            require(msg.sender == ownerOf(tokenId) || ownerOf(tokenId) == address(this), "You don't own this token.");
            _takeOffAndBurn(tokenId);
        }
        _safeMint(to, newTokenId);

        emit AdherentRegenerated(msg.sender, to, newTokenId, tokenIds);
    }

    /// @notice Wear accessories.
    /// @param signature sign
    /// @param tokenId Token ID
    /// @param isEquipped Array of accessory equipped setting of each type of accessory
    /// @param isEquipped Specify if each accessory type (0~7) is equipped.
    /// @param accessoryTokenIds Array of accessory token IDs of each accessory type
    /// @param accessoryTokenIds If the corresponding type of accessory will not be equipped, just simply specify 0.
    function wear(bytes memory signature, uint256 tokenId, bool[8] calldata isEquipped, uint256[8] calldata accessoryTokenIds) external whenNotPaused nonReentrant {
        require(ownerOf(tokenId) == msg.sender || ownerOf(tokenId) == address(this), "You don't own this token.");
        require(_isValidWearSignature(signature, tokenId, isEquipped, accessoryTokenIds), "Signature is error.");
        _wear(msg.sender, tokenId, isEquipped, accessoryTokenIds);
    }

    /// @notice Take off all accessories.
    /// @param signature sign
    /// @param tokenId Token ID
    /// @dev Unequipped accessories will send to token owner
    /// @dev Only token owner can do this
    function takeOff(bytes memory signature, uint256 tokenId) external whenNotPaused nonReentrant {
        require(ownerOf(tokenId) == msg.sender || ownerOf(tokenId) == address(this), "You don't own this token.");
        require(_isValidTakeOffSignature(signature, tokenId), "Signature is error.");
        _takeOff(tokenId);
    }

    /// @notice Returns token accessory information
    /// @param tokenId Token Id
    /// @return isEquipped Array of accessory equipped status of each type of accessory
    /// @return accessoryTokenIds Array of accessory token ID
    /// @dev Ignore token ID if accessory is not equipped.
    function tokenEquippedAccessories(uint256 tokenId) public view returns (bool[8] memory, uint256[8] memory)
    {
        bool[8] memory isEquipped;
        uint256[8] memory accessoryTokenIds;
        (isEquipped, accessoryTokenIds) = _tokenEquippedAccessories(tokenId);
        for (uint256 i; i < 8; i++) {
            if (!isEquipped[i]) {
                accessoryTokenIds[i] = 0;
            }
        }
        return (isEquipped, accessoryTokenIds);
    }

    /// @notice Returns if token accessory is equipped
    /// @param tokenId Token Id
    /// @param accessoryTokenId Accessory Token Id
    /// @return isEquipped
    /// @dev Ignore token ID if accessory is not equipped.
    function isTokenEquippedAccessory(uint256 tokenId, uint256 accessoryTokenId) public view returns (bool)
    {
        bool[8] memory isEquipped;
        uint256[8] memory accessoryTokenIds;
        (isEquipped, accessoryTokenIds) = _tokenEquippedAccessories(tokenId);
        for (uint256 i; i < 8; i++) {
            if (isEquipped[i] && accessoryTokenIds[i] == accessoryTokenId) {
                return true;
            }
        }
        return false;
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

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721Enumerable, ERC1155Receiver) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    // ======================================================== Internal Functions
    /// Verify Mint Signature
    function _isValidMintSignature(bytes memory signature, uint256 tokenId, address to) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(name(), msg.sender, tokenId, to));
        return _isValidHash(hash, signature);
    }

    /// Verify Regenerate Signature
    function _isValidRegenerateSignature(bytes memory signature, uint256[] calldata tokenIds, uint256 newTokenId, address to) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(name(), msg.sender, tokenIds, newTokenId, to));
        return _isValidHash(hash, signature);
    }
    /// Verify Wear Signature
    function _isValidWearSignature(bytes memory signature, uint256 tokenId, bool[8] calldata isEquipped, uint256[8] calldata accessoryTokenIds) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(name(), msg.sender, tokenId, isEquipped, accessoryTokenIds, tokenAccessoryOperationCount[tokenId]));
        return _isValidHash(hash, signature);
    }
    /// Verify Take off Signature
    function _isValidTakeOffSignature(bytes memory signature, uint256 tokenId) internal view returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(name(), msg.sender, tokenId, tokenAccessoryOperationCount[tokenId]));
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

    function _wear(address _requestFrom, uint256 _tokenId, bool[8] calldata _isEquipped, uint256[8] calldata _accessoryTokenIds) private whenNotPaused {
        require(address(accessoryAddress) != address(0), "Accessory contract address is empty.");

        (bool[8] memory isEquipped, uint256[8] memory accessoryTokenIds) = _tokenEquippedAccessories(_tokenId);
        uint256 equippedCounter;
        uint256 unequippedCounter;
        uint256[8] memory batchEquippedTokenIds;
        uint256[8] memory batchUnequippedTokenIds;

        for (uint256 i; i < 8; i++) {
            if (_isEquipped[i]) {
                if (isEquipped[i]) {
                    if (_accessoryTokenIds[i] == accessoryTokenIds[i]) {
                        continue;
                    }
                    batchUnequippedTokenIds[unequippedCounter] = accessoryTokenIds[i];
                    unequippedCounter += 1;
                }
                require(accessoryAddress.accessoryType(_accessoryTokenIds[i]) == i, "Accessory type mismatch.");
                require(accessoryAddress.balanceOf(address(accessoryAddress), _accessoryTokenIds[i]) > 0, "Accessory is not enough.");
                batchEquippedTokenIds[equippedCounter] = _accessoryTokenIds[i];
                equippedCounter += 1;
            } else if (isEquipped[i]) {
                require(accessoryAddress.balanceOf(address(this), accessoryTokenIds[i]) > 0, "Self accessory is not enough.");
                batchUnequippedTokenIds[unequippedCounter] = accessoryTokenIds[i];
                unequippedCounter += 1;
            }
        }

        _batchTransferAccessories(
            address(accessoryAddress),
            address(this),
            batchEquippedTokenIds,
            equippedCounter
        );
        _batchTransferAccessories(
            address(this),
            address(accessoryAddress),
            batchUnequippedTokenIds,
            unequippedCounter
        );

        uint256 encodedAccessories = 0;
        for (uint256 i; i < 8; i++) {
            encodedAccessories <<= 32;
            encodedAccessories |= _accessoryTokenIds[i].toUint32();
        }

        Accessory storage accessoryData = tokenAccessoryData[_tokenId];
        accessoryData.isEquipped = _isEquipped;
        accessoryData.encodedAccessories = encodedAccessories;

        if (unequippedCounter + equippedCounter > 0) {
            tokenAccessoryOperationCount[_tokenId] += 1;
        }

        uint256 operationCount = tokenAccessoryOperationCount[_tokenId];
        emit AccessoryWeared(
            _requestFrom,
            _tokenId,
            isEquipped,
            accessoryTokenIds,
            _isEquipped,
            _accessoryTokenIds,
            operationCount
        );
    }

    function _takeOff(uint256 tokenId) private {
        require(address(accessoryAddress) != address(0), "Accessory contract address is empty.");

        (bool[8] memory isEquipped, uint256[8] memory accessoryTokenIds) = _tokenEquippedAccessories(tokenId);
        uint256 unequippedCounter;
        uint256[8] memory batchUnequippedTokenIds;
        for (uint256 i; i < 8; i++) {
            if (isEquipped[i]) {
                batchUnequippedTokenIds[unequippedCounter] = accessoryTokenIds[i];
                unequippedCounter += 1;
            }
        }
        uint256[] memory unequippedTransferredTokens = _batchTransferAccessories(
            address(this),
            address(accessoryAddress),
            batchUnequippedTokenIds,
            unequippedCounter
        );
        delete tokenAccessoryData[tokenId];

        if (unequippedCounter > 0) {
            tokenAccessoryOperationCount[tokenId] += 1;
        }

        emit AccessoryTakenOff(
            msg.sender,
            tokenId,
            accessoryTokenIds,
            unequippedTransferredTokens,
            tokenAccessoryOperationCount[tokenId]
        );
    }

    function _batchTransferAccessories(
        address _from,
        address _to,
        uint256[8] memory _ids,
        uint256 _transferCounter
    ) private returns (uint256[] memory tokenIds) {
        if (_transferCounter > 0) {
            tokenIds = new uint256[](_transferCounter);
            uint256[] memory amount = new uint256[](_transferCounter);

            for (uint256 i; i < _transferCounter; i++) {
                tokenIds[i] = _ids[i];
                amount[i] = 1;
            }

            if (_from != _to) {
                accessoryAddress.contractBatchTransfer(
                    _from,
                    _to,
                    tokenIds,
                    amount
                );
            }
        }
    }

    function _takeOffAndBurn(uint256 tokenId) private {
        require(address(accessoryAddress) != address(0), "Accessory contract address is empty.");

        (bool[8] memory isEquipped, uint256[8] memory accessoryTokenIds) = _tokenEquippedAccessories(tokenId);
        uint256[8] memory batchUnequippedTokenIds;
        uint256 unequippedCounter;
        for (uint256 i; i < 8; i++) {
            if (isEquipped[i]) {
                batchUnequippedTokenIds[unequippedCounter] = accessoryTokenIds[i];
                unequippedCounter += 1;
            }
        }
        if (unequippedCounter > 0) {
            uint256[] memory tokenIds = new uint256[](unequippedCounter);
            uint256[] memory amounts = new uint256[](unequippedCounter);
            for (uint256 i; i < unequippedCounter; i++) {
                tokenIds[i] = batchUnequippedTokenIds[i];
                amounts[i] = 1;
            }
            accessoryAddress.contractBatchBurn(
                address(this),
                tokenIds,
                amounts
            );
        }
        delete tokenAccessoryData[tokenId];
        delete tokenAccessoryOperationCount[tokenId];
        _burn(tokenId);
    }

    function _tokenEquippedAccessories(uint256 _tokenId) private view returns (bool[8] memory, uint256[8] memory)
    {
        uint256[8] memory accessoryTokenIds;

        Accessory storage accessoryData = tokenAccessoryData[_tokenId];
        uint256 accessories = accessoryData.encodedAccessories;

        for (uint256 i; i < 8; i++) {
            accessoryTokenIds[7 - i] = accessories & 0xffffffff;
            accessories >>= 32;
        }

        return (accessoryData.isEquipped, accessoryTokenIds);
    }
} // End of Contract
