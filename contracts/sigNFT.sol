// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts-ethereum-package/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts-ethereum-package/contracts/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract sigNFT is OwnableUpgradeable {
    using SafeMath for uint256;
    using ECDSA for bytes32;

    struct Signature {
        address signer;
        string message;
    }

    struct WhitelistToggle {
        bool toggled;
        bool whitelist;
    }  

    // Signatures
    mapping (address => mapping (uint256 => Signature[])) internal signatures;
    mapping (address => mapping (uint256 => mapping (address => uint256))) internal signatureIndexOfSigner;
    mapping (address => mapping (address => mapping (uint256 => bool))) internal hasSignedNFT;

    // Whitelisting
    mapping (address => bool) internal whitelistIsDefault;
    mapping (address => mapping (uint256 => mapping (address => bool))) internal whitelistedSigner;
    mapping (address => mapping (uint256 => WhitelistToggle)) internal tokenIsUsingWhitelist;

    // Token Controllers
    mapping (address => mapping(address => bool)) internal contractController;
    mapping (address => bool) internal noController;
    mapping (address => bool) internal contractActive;

    function initialize() public initializer {
        OwnableUpgradeable.__Ownable_init();
    }

    function signNFT(address _tokenAddress, uint256 _tokenID, string memory _message, bytes memory _signature) public {
        IERC721 erc721 = IERC721(_tokenAddress);
        require(erc721.ownerOf(_tokenID) != address(0), "Token doesn't exist");
        
        require(
                whitelistedSigner[_tokenAddress][_tokenID][msg.sender] ||
                (tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled && 
                !tokenIsUsingWhitelist[_tokenAddress][_tokenID].whitelist) ||
                (!tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled &&
                !whitelistIsDefault[_tokenAddress]),
                "Not autorized to sign"
                );
        require(!hasSignedNFT[_tokenAddress][msg.sender][_tokenID], "Already signed by sender");
        require(bytes(_message).length > 0, "Empty message");
        
        bytes32 messageHash = keccak256(abi.encodePacked(_message));
        require(messageHash.recover(_signature) == msg.sender, "Invalid Signature");

        Signature memory newSignature = Signature(msg.sender, _message);
        signatures[_tokenAddress][_tokenID].push(newSignature);
        signatureIndexOfSigner[_tokenAddress][_tokenID][msg.sender] = signatures[_tokenAddress][_tokenID].length - 1;
        hasSignedNFT[_tokenAddress][msg.sender][_tokenID] = true;
    }

    function getSignatures(address _tokenAddress, uint256 _tokenID) public view returns(address[] memory signers, string[] memory messages) {
        IERC721 erc721 = IERC721(_tokenAddress);
        require(erc721.ownerOf(_tokenID) != address(0), "Token doesn't exist");

        signers = new address[](signatures[_tokenAddress][_tokenID].length);
        messages = new string[](signatures[_tokenAddress][_tokenID].length);

        for(uint256 i = 0; i < signatures[_tokenAddress][_tokenID].length; i++) {
            signers[i] = signatures[_tokenAddress][_tokenID][i].signer;
            messages[i] = signatures[_tokenAddress][_tokenID][i].message;
        }

        return (signers, messages);
    }

    function addToWhiteList(address _tokenAddress, uint256 _tokenID, address _whitelistedSigner) public {
        if(noController[_tokenAddress]) {
            IERC721 erc721 = IERC721(_tokenAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractController[_tokenAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        if(!tokenIsUsingWhitelist[_tokenAddress][_tokenID].whitelist) {
            tokenIsUsingWhitelist[_tokenAddress][_tokenID].whitelist = true;
            tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled = true;
        }
        whitelistedSigner[_tokenAddress][_tokenID][_whitelistedSigner] = true;
    }

    function removeFromWhitelist(address _tokenAddress, uint256 _tokenID, address _whitelistedSigner) public {
        if(noController[_tokenAddress]) {
            IERC721 erc721 = IERC721(_tokenAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractController[_tokenAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        whitelistedSigner[_tokenAddress][_tokenID][_whitelistedSigner] = false;
    }

    function activateWhitelist(address _tokenAddress, uint256 _tokenID) public {
        if(noController[_tokenAddress]) {
            IERC721 erc721 = IERC721(_tokenAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractController[_tokenAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled = true;
        tokenIsUsingWhitelist[_tokenAddress][_tokenID].whitelist = true;
    }

    function deactivateWhitelist(address _tokenAddress, uint256 _tokenID) public {
        if(noController[_tokenAddress]) {
            IERC721 erc721 = IERC721(_tokenAddress);
            require(erc721.ownerOf(_tokenID) == msg.sender, "Can't modify whitelist of other tokens");
        } else {
            require(contractController[_tokenAddress][msg.sender], "Only controllers are allowed to modify the whitelist");
        }

        tokenIsUsingWhitelist[_tokenAddress][_tokenID].toggled = true;
        tokenIsUsingWhitelist[_tokenAddress][_tokenID].whitelist = false;
    }

    function activateContract(address _tokenAddress, address[] memory _tokenControllers, bool _whitelistAsDefault) public onlyOwner() {
        contractActive[_tokenAddress] = true;
        if(_tokenControllers.length > 0){
            for(uint256 i = 0; i < _tokenControllers.length; i++) {
                contractController[_tokenAddress][_tokenControllers[i]] = true;
            }
        } else {
            noController[_tokenAddress] = true;
        }
        whitelistIsDefault[_tokenAddress] = _whitelistAsDefault;
    }

    function addControllers(address _tokenAddress, address[] memory _tokenControllers) public {
        require(contractController[_tokenAddress][msg.sender] || owner() == msg.sender, "Not allowed to modify controllers");
        for(uint256 i = 0; i < _tokenControllers.length; i++) {
                contractController[_tokenAddress][_tokenControllers[i]] = true;
        }
    }

    function removeControllers(address _tokenAddress, address[] memory _tokenControllers) public {
        require(contractController[_tokenAddress][msg.sender] || owner() == msg.sender, "Not allowed to modify controllers");
        for(uint256 i = 0; i < _tokenControllers.length; i++) {
                contractController[_tokenAddress][_tokenControllers[i]] = false;
        }
    }
}